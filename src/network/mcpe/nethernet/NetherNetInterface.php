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

use amber\nethernet\backend\ExtWebRtcPeer;
use amber\nethernet\Channel;
use amber\nethernet\Connection;
use amber\nethernet\identity\IdentityHandler;
use amber\nethernet\signaling\HttpSignalingServer;
use amber\nethernet\signaling\ServerMetadata;
use amber\nethernet\Transport;
use amber\nethernet\TransportConfig;
use amber\nethernet\TransportException;
use amber\nethernet\TransportListener;
use pocketmine\lang\KnownTranslationFactory;
use pocketmine\network\mcpe\compression\ZlibCompressor;
use pocketmine\network\mcpe\convert\TypeConverter;
use pocketmine\network\mcpe\EntityEventBroadcaster;
use pocketmine\network\mcpe\NetworkSession;
use pocketmine\network\mcpe\PacketBroadcaster;
use pocketmine\network\mcpe\protocol\PacketPool;
use pocketmine\network\mcpe\protocol\ProtocolInfo;
use pocketmine\network\NetworkInterface;
use pocketmine\network\NetworkInterfaceStartException;
use pocketmine\network\PacketHandlingException;
use pocketmine\Server;
use pocketmine\timings\Timings;
use pocketmine\utils\Utils;
use function hrtime;
use function implode;

/**
 * Accepts Bedrock clients over NetherNet (WebRTC data channels negotiated through
 * HTTP signaling on the server's TCP port). Unlike RakNet, game batches carry no
 * 0xfe header, so payloads are passed to the session unchanged.
 */
final class NetherNetInterface implements NetworkInterface, TransportListener{
	private ?HttpSignalingServer $signaling = null;
	/** @var NetworkSession[] */
	private array $sessions = [];
	private string $name = "";

	public function __construct(
		private readonly Server $server,
		private readonly string $ip,
		private readonly int $port,
		private readonly bool $requireIdentity,
		private readonly IdentityHandler $identityHandler,
		private readonly PacketBroadcaster $packetBroadcaster,
		private readonly EntityEventBroadcaster $entityEventBroadcaster,
		private readonly TypeConverter $typeConverter,
		private readonly TransportConfig $config = new TransportConfig()
	){}

	public function start() : void{
		try{
			ExtWebRtcPeer::assertAvailable();
			$config = $this->config;
			$signaling = new HttpSignalingServer(
				$config,
				$this,
				$this->getMetadata(...),
				fn(TransportListener $listener) : Transport => new Transport(
					$config,
					$this->identityHandler,
					$listener,
					static fn() : ExtWebRtcPeer => new ExtWebRtcPeer($config),
					$this->requireIdentity
				)
			);
			$signaling->bind($this->ip, $this->port);
		}catch(TransportException $e){
			throw new NetworkInterfaceStartException($e->getMessage(), 0, $e);
		}
		$this->signaling = $signaling;
	}

	public function setName(string $name) : void{
		$this->name = $name;
	}

	private function getMetadata() : ServerMetadata{
		$info = $this->server->getQueryInformation();
		return new ServerMetadata(
			$this->name,
			ProtocolInfo::CURRENT_PROTOCOL,
			ProtocolInfo::MINECRAFT_VERSION_NETWORK,
			$info->getWorld(),
			$info->getPlayerCount(),
			$info->getMaxPlayerCount(),
			$this->typeConverter->coreGameModeToProtocol($this->server->getGamemode())
		);
	}

	public function tick() : void{
		if($this->signaling === null){
			return;
		}
		Timings::$connection->startTiming();
		try{
			$this->signaling->poll(hrtime(true) / 1_000_000_000);
		}finally{
			Timings::$connection->stopTiming();
		}
	}

	public function shutdown() : void{
		$this->signaling?->shutdown();
		$this->signaling?->poll(hrtime(true) / 1_000_000_000);
		$this->signaling = null;
	}

	public function onAnswer(int $id, string $answerSdp) : void{
		//NOOP: the signaling server replies to the client
	}

	public function onOpen(Connection $connection) : void{
		$id = $connection->getId();
		$this->sessions[$id] = new NetworkSession(
			$this->server,
			$this->server->getNetwork()->getSessionManager(),
			PacketPool::getInstance(),
			new NetherNetPacketSender(
				$connection,
				fn(int $receiptId) => $this->onSendComplete($id, $receiptId),
				fn(string $reason) => $this->close($id, $reason)
			),
			$this->packetBroadcaster,
			$this->entityEventBroadcaster,
			ZlibCompressor::getInstance(),
			$this->typeConverter,
			$this->signaling?->getRemoteAddress($id) ?? "0.0.0.0",
			0
		);
	}

	public function onPayload(Connection $connection, string $payload, Channel $channel) : void{
		$session = $this->sessions[$connection->getId()] ?? null;
		if($session === null){
			return;
		}
		$name = $session->getDisplayName();
		try{
			$session->handleEncoded($payload);
		}catch(PacketHandlingException $e){
			$session->disconnectWithError(
				reason: "Bad packet: " . $e->getMessage(),
				disconnectScreenMessage: KnownTranslationFactory::pocketmine_disconnect_error_badPacket()
			);
			//intentionally doesn't use logException, we don't want spammy packet error traces to appear in release mode
			$session->getLogger()->debug(implode("\n", Utils::printableExceptionInfo($e)));
		}catch(\Throwable $e){
			//record the name of the player who caused the crash, to make it easier to find the reproducing steps
			$this->server->getLogger()->emergency("Crash occurred while handling a packet from session: $name");
			throw $e;
		}
	}

	public function onClose(int $id, string $code, string $reason) : void{
		$session = $this->sessions[$id] ?? null;
		if($session === null){
			return;
		}
		unset($this->sessions[$id]);
		$session->onClientDisconnect(match($code){
			"closed" => KnownTranslationFactory::pocketmine_disconnect_clientDisconnect(),
			"peer_failed" => KnownTranslationFactory::pocketmine_disconnect_error_timeout(),
			default => "NetherNet connection closed: $reason ($code)"
		});
	}

	private function onSendComplete(int $sessionId, int $receiptId) : void{
		($this->sessions[$sessionId] ?? null)?->handleAckReceipt($receiptId);
	}

	public function close(int $sessionId, string $reason) : void{
		if(isset($this->sessions[$sessionId])){
			unset($this->sessions[$sessionId]);
			$this->signaling?->getTransport()->cancel($sessionId, $reason);
		}
	}
}
