<?php

/*
 *
 *     _             _
 *    / \   _ __ ___ | |__   ___ _ __
 *   / _ \ | '_ ` _ \| '_ \ / _ \ '__|
 *  / ___ \| | | | | | |_) |  __/ |
 * /_/   \_\_| |_| |_|_.__/ \___|_|
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * @author AmberPM Team
 * @link https://github.com/Amber-PM/Amber
 *
 *
 */

declare(strict_types=1);

namespace pocketmine\network\mcpe\nethernet;

use amber\nethernet\identity\IdentityHandler;
use amber\nethernet\identity\Jws;
use amber\nethernet\identity\PeerIdentity;
use amber\nethernet\identity\ServerIdentity;
use amber\nethernet\TransportException;
use pocketmine\network\mcpe\auth\AuthKeyProvider;
use pocketmine\network\mcpe\JwtException;
use pocketmine\network\mcpe\JwtUtils;
use function base64_decode;
use function is_int;
use function is_string;
use function time;

/**
 * Early, signaling-time check of the client's a=identity assertion. This only
 * decides whether the WebRTC connection is worth setting up; the usual login
 * verification still runs once the game protocol starts.
 */
final class NetherNetIdentityHandler implements IdentityHandler{
	public function __construct(
		private readonly AuthKeyProvider $authKeyProvider,
		private readonly ServerIdentity $serverIdentity
	){}

	public function verifyClient(string $token, string $canonicalFingerprints, string $detachedJws, \Closure $complete) : \Closure{
		$request = new class{
			public bool $cancelled = false;
		};
		try{
			[$header, ] = JwtUtils::parse($token);
		}catch(JwtException $e){
			$complete(null, new TransportException('identity_invalid', 'Malformed GameServerToken: ' . $e->getMessage()));
			return static function() : void{};
		}
		$keyId = $header['kid'] ?? null;
		if(!is_string($keyId)){
			$complete(null, new TransportException('identity_invalid', 'GameServerToken has no key ID'));
			return static function() : void{};
		}
		$this->authKeyProvider->getKey($keyId)->onCompletion(
			function(array $issuerAndKey) use ($request, $token, $canonicalFingerprints, $detachedJws, $complete) : void{
				if($request->cancelled){
					return;
				}
				[$issuer, $signingKey] = $issuerAndKey;
				try{
					$complete(self::verify($token, $issuer, $signingKey, $canonicalFingerprints, $detachedJws), null);
				}catch(TransportException $e){
					$complete(null, $e);
				}
			},
			function() use ($request, $keyId, $complete) : void{
				if(!$request->cancelled){
					$complete(null, new TransportException('identity_invalid', "Unrecognized authentication key ID: $keyId"));
				}
			}
		);
		return static function() use ($request) : void{
			$request->cancelled = true;
		};
	}

	/** @throws TransportException */
	private static function verify(string $token, string $issuer, string $signingKey, string $canonicalFingerprints, string $detachedJws) : PeerIdentity{
		try{
			if(!JwtUtils::verify($token, $signingKey, ec: false)){
				throw new TransportException('identity_invalid', 'Invalid GameServerToken signature');
			}
			[, $claims, ] = JwtUtils::parse($token);
		}catch(JwtException $e){
			throw new TransportException('identity_invalid', $e->getMessage(), $e);
		}
		if(($claims['iss'] ?? null) !== $issuer){
			throw new TransportException('identity_invalid', 'Invalid GameServerToken issuer');
		}
		$now = time();
		$expiry = $claims['exp'] ?? null;
		$notBefore = $claims['nbf'] ?? null;
		if(!is_int($expiry) || $expiry <= $now || (is_int($notBefore) && $notBefore > $now + 60)){
			throw new TransportException('identity_invalid', 'GameServerToken is expired or not yet valid');
		}
		$cpk = $claims['cpk'] ?? null;
		$publicKeyDer = is_string($cpk) ? base64_decode($cpk, true) : false;
		if($publicKeyDer === false){
			throw new TransportException('identity_invalid', 'GameServerToken has an invalid cpk claim');
		}
		// Proves the token holder generated the DTLS certificate advertised in the offer.
		Jws::verifyCompact($detachedJws, $canonicalFingerprints, Jws::derToPem($publicKeyDer));

		$xuid = $claims['xid'] ?? '';
		return new PeerIdentity(is_string($xuid) ? $xuid : '', $publicKeyDer, $claims);
	}

	public function signServer(string $canonicalFingerprints, int $now) : string{
		return $this->serverIdentity->createAssertion($canonicalFingerprints, $now);
	}
}
