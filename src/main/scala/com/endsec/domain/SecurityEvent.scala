package com.endsec.domain

import java.time.Instant
import java.util.UUID

// Core domain models

/** Base trait for all security events */
sealed trait SecurityEvent:
  def id: UUID
  def timestamp: Instant
  def severity: Severity
  def source: String
  def details: String

/** Represents the severity level of security events */
enum Severity:
  case Critical, High, Medium, Low, Info

/** Represents a detected malware or virus */
final case class VirusDetection(
                                 id: UUID = UUID.randomUUID(),
                                 timestamp: Instant = Instant.now(),
                                 severity: Severity,
                                 source: String,
                                 details: String,
                                 filePath: String,
                                 virusSignature: String,
                                 quarantined: Boolean
                               ) extends SecurityEvent

/** Represents a vulnerability detected in the system */
final case class VulnerabilityDetection(
                                         id: UUID = UUID.randomUUID(),
                                         timestamp: Instant = Instant.now(),
                                         severity: Severity,
                                         source: String,
                                         details: String,
                                         affectedComponent: String,
                                         cveId: Option[String],
                                         remediation: Option[String]
                                       ) extends SecurityEvent

/** Represents an anomaly in network traffic */
final case class TrafficAnomaly(
                                 id: UUID = UUID.randomUUID(),
                                 timestamp: Instant = Instant.now(),
                                 severity: Severity,
                                 source: String,
                                 details: String,
                                 protocol: String,
                                 sourceIp: String,
                                 destinationIp: String,
                                 sourcePort: Int,
                                 destinationPort: Int,
                                 bytesSent: Long,
                                 bytesReceived: Long,
                                 anomalyType: AnomalyType
                               ) extends SecurityEvent

/** Types of network traffic anomalies */
enum AnomalyType:
  case DataExfiltration, BruteForce, DDoS, UnusualProtocol, SuspiciousConnection

/** Represents a generic security threat */
final case class SecurityThreat(
                                 id: UUID = UUID.randomUUID(),
                                 timestamp: Instant = Instant.now(),
                                 severity: Severity,
                                 source: String,
                                 details: String,
                                 threatType: ThreatType,
                                 targetResource: String,
                                 indicators: List[String]
                               ) extends SecurityEvent

/** Types of security threats */
enum ThreatType:
  case Malware, Ransomware, Phishing, Backdoor, UnauthorizedAccess, PrivilegeEscalation

/** Encapsulates a scan result for any type of security scan */
final case class ScanResult[A <: SecurityEvent](
                                                 scanId: UUID,
                                                 scanStartTime: Instant,
                                                 scanEndTime: Instant,
                                                 scanType: ScanType,
                                                 events: List[A],
                                                 hostInfo: HostInfo
                                               )

/** The type of scan performed */
enum ScanType:
  case VirusScan, VulnerabilityScan, NetworkScan, FullScan

/** Information about the host being scanned */
final case class HostInfo(
                           hostId: String,
                           hostname: String,
                           ipAddress: String,
                           os: String,
                           osVersion: String,
                           cpuArchitecture: String
                         )