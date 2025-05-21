package com.endsec.utils

import cats.effect.*
import cats.syntax.all.*
import io.circe.*
import io.circe.generic.auto.*
import io.circe.syntax.*
import com.endsec.domain.*
import com.endsec.services.NetworkStatus
import fs2.io.file.Path

import java.time.Instant
import java.time.format.DateTimeFormatter
import scala.reflect.ClassTag

/** Provides formatted output of scan results and events */
trait OutputFormatter[F[_]]:
  def formatDetection[A <: SecurityEvent](detection: A, json: Boolean): F[Unit]
  def formatScanResult[A <: SecurityEvent](result: ScanResult[A], json: Boolean): F[Unit]
  def formatEvents[A <: SecurityEvent](events: List[A], json: Boolean): F[Unit]
  def formatNetworkStatus(status: NetworkStatus, json: Boolean): F[Unit]

object OutputFormatter:
  def apply[F[_]: Sync]: OutputFormatter[F] = new OutputFormatterImpl[F]()

private class OutputFormatterImpl[F[_]: Sync]() extends OutputFormatter[F]:
  private val dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")

  // Circe encoders for domain models
  private given Encoder[Instant] = Encoder.encodeString.contramap[Instant](
    instant => instant.toString
  )

  private given Encoder[Path] = Encoder.encodeString.contramap[Path](
    path => path.toString
  )

  given Encoder[Severity] = Encoder.encodeString.contramap[Severity](_.toString)
  given Encoder[AnomalyType] = Encoder.encodeString.contramap[AnomalyType](_.toString)
  given Encoder[ThreatType] = Encoder.encodeString.contramap[ThreatType](_.toString)
  given Encoder[ScanType] = Encoder.encodeString.contramap[ScanType](_.toString)

  def formatDetection[A <: SecurityEvent](detection: A, json: Boolean): F[Unit] =
    if json then
      Sync[F].delay(println(detection.asJson.noSpaces))
    else
      detection match
        case v: VirusDetection =>
          Sync[F].delay {
            println(s"""
                       |Virus Detection:
                       |  ID: ${v.id}
                       |  Time: ${formatTime(v.timestamp)}
                       |  Severity: ${v.severity}
                       |  File: ${v.filePath}
                       |  Virus: ${v.virusSignature} (${v.details})
                       |  Quarantined: ${v.quarantined}
            """.stripMargin)
          }

        case v: VulnerabilityDetection =>
          Sync[F].delay {
            println(s"""
                       |Vulnerability Detection:
                       |  ID: ${v.id}
                       |  Time: ${formatTime(v.timestamp)}
                       |  Severity: ${v.severity}
                       |  Component: ${v.affectedComponent}
                       |  CVE ID: ${v.cveId.getOrElse("N/A")}
                       |  Details: ${v.details}
                       |  Remediation: ${v.remediation.getOrElse("N/A")}
            """.stripMargin)
          }

        case t: TrafficAnomaly =>
          Sync[F].delay {
            println(s"""
                       |Traffic Anomaly:
                       |  ID: ${t.id}
                       |  Time: ${formatTime(t.timestamp)}
                       |  Severity: ${t.severity}
                       |  Type: ${t.anomalyType}
                       |  Connection: ${t.sourceIp}:${t.sourcePort} -> ${t.destinationIp}:${t.destinationPort} (${t.protocol})
                       |  Details: ${t.details}
            """.stripMargin)
          }

        case s: SecurityThreat =>
          Sync[F].delay {
            println(s"""
                       |Security Threat:
                       |  ID: ${s.id}
                       |  Time: ${formatTime(s.timestamp)}
                       |  Severity: ${s.severity}
                       |  Type: ${s.threatType}
                       |  Target: ${s.targetResource}
                       |  Details: ${s.details}
                       |  Indicators: ${s.indicators.mkString(", ")}
            """.stripMargin)
          }

        case _ =>
          Sync[F].delay {
            println(s"""
                       |Security Event:
                       |  ID: ${detection.id}
                       |  Time: ${formatTime(detection.timestamp)}
                       |  Severity: ${detection.severity}
                       |  Source: ${detection.source}
                       |  Details: ${detection.details}
            """.stripMargin)
          }

  def formatScanResult[A <: SecurityEvent](result: ScanResult[A], json: Boolean): F[Unit] =
    if json then
      Sync[F].delay(println(result.asJson.noSpaces))
    else
      Sync[F].delay {
        println(s"""
                   |Scan Result:
                   |  Scan ID: ${result.scanId}
                   |  Type: ${result.scanType}
                   |  Start Time: ${formatTime(result.scanStartTime)}
                   |  End Time: ${formatTime(result.scanEndTime)}
                   |  Duration: ${(result.scanEndTime.toEpochMilli - result.scanStartTime.toEpochMilli) / 1000.0} seconds
                   |  Host: ${result.hostInfo.hostname} (${result.hostInfo.ipAddress})
                   |  OS: ${result.hostInfo.os} ${result.hostInfo.osVersion} (${result.hostInfo.cpuArchitecture})
                   |  Detected Events: ${result.events.size}
                   |""".stripMargin)

        if (result.events.nonEmpty) {
          println("Events:")
          result.events.zipWithIndex.foreach { case (event, i) =>
            println(s"  ${i + 1}. [${event.severity}] ${event.details}")
          }
        }
      }

  def formatEvents[A <: SecurityEvent](events: List[A], json: Boolean): F[Unit] =
    if json then
      Sync[F].delay(println(events.asJson.noSpaces))
    else
      Sync[F].delay {
        if (events.isEmpty) {
          println("No security events found.")
        } else {
          println(s"Found ${events.size} security events:")
          events.zipWithIndex.foreach { case (event, i) =>
            println(s"  ${i + 1}. [${formatTime(event.timestamp)}] [${event.severity}] ${event.source}: ${event.details}")
          }
        }
      }

  def formatNetworkStatus(status: NetworkStatus, json: Boolean): F[Unit] =
    if json then
      Sync[F].delay(println(status.asJson.noSpaces))
    else
      Sync[F].delay {
        println(s"""
                   |Network Monitoring Status:
                   |  Running: ${status.isRunning}
                   |  Since: ${status.monitoringSince.map(formatTime).getOrElse("Not running")}
                   |  Interfaces: ${status.networkInterfaces.mkString(", ")}
                   |  Anomalies Detected: ${status.anomalyCount}
                   |  Traffic Statistics:
                   |    Sent: ${formatBytes(status.trafficStats.totalBytesSent)}
                   |    Received: ${formatBytes(status.trafficStats.totalBytesReceived)}
                   |    Connections/min: ${status.trafficStats.connectionsPerMinute}
                   |    Active Connections: ${status.trafficStats.activeConnections}
        """.stripMargin)
      }

  private def formatTime(instant: Instant): String =
    dateFormatter.format(instant.atZone(java.time.ZoneId.systemDefault()))

  private def formatBytes(bytes: Long): String =
    if (bytes < 1024) s"$bytes B"
    else if (bytes < 1024 * 1024) f"${bytes / 1024.0}%.2f KB"
    else if (bytes < 1024 * 1024 * 1024) f"${bytes / 1024.0 / 1024.0}%.2f MB"
    else f"${bytes / 1024.0 / 1024.0 / 1024.0}%.2f GB"