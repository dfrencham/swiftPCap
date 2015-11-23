//
//  main.swift
//  swifttest
//
//  Created by Danny Frencham on 11/11/2015.
//  Copyright © 2015 Danny Frencham. All rights reserved.
//

import Foundation

print("pcap test")

let packetCap = PacketCapture()
let interface = "en0"
let numberOfPackets = Int32(10)
packetCap.doPacketCapture(interface, numberOfPackets: numberOfPackets)




