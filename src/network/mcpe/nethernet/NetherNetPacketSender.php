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

use amber\nethernet\Channel;
use amber\nethernet\Connection;
use amber\nethernet\SendResult;
use pocketmine\network\mcpe\PacketSender;

/**
 * NetherNet has no RakNet-style ACKs. Send receipts are therefore completed once
 * the payload has been handed to the SCTP stack, which only accepts more data
 * while its send buffer has room. This still gives receipt users such as
 * resource pack downloads real flow control.
 */
final class NetherNetPacketSender implements PacketSender{
	private bool $closed = false;

	/**
	 * @phpstan-param \Closure(int $receiptId) : void $onSendComplete
	 * @phpstan-param \Closure(string $reason) : void $onClose
	 */
	public function __construct(
		private readonly Connection $connection,
		private readonly \Closure $onSendComplete,
		private readonly \Closure $onClose
	){}

	public function send(string $payload, bool $immediate, ?int $receiptId) : void{
		if($this->closed){
			return;
		}
		$accepted = null;
		if($receiptId !== null){
			$onSendComplete = $this->onSendComplete;
			$accepted = static function(bool $sent) use ($onSendComplete, $receiptId) : void{
				if($sent){
					$onSendComplete($receiptId);
				}
			};
		}
		$result = $this->connection->send($payload, Channel::RELIABLE, $immediate, $accepted);
		if($result === SendResult::BACKPRESSURE){
			//reliable game data cannot be dropped; a client this far behind is not keeping up
			$this->close("Outgoing NetherNet queue overflow");
		}
	}

	public function close(string $reason = "unknown reason") : void{
		if(!$this->closed){
			$this->closed = true;
			($this->onClose)($reason);
		}
	}
}
