package com.endsec.services

import cats.effect.*
import cats.syntax.all.*
import fs2.Stream
import org.typelevel.log4cats.Logger
import org.typelevel.log4cats.slf4j.Slf4jLogger

import com.endsec.domain.*
import com.endsec.repositories.SecurityEventRepository
import com.endsec.utils.{NetworkUtils, SystemInfo}

import java.time.Instant
import java.util.UUID
import scala.concurrent.duration.*
import scala.util.Random

/** Service for monitoring network traffic for anomalies */
trait NetworkMonitorService[F[_]]:
  def startMonitoring: F[Fiber[F, Throwable, Unit]]
  def stopMonitoring: F[Unit]
  def getCurrentStatus: F[NetworkStatus]
  def getRecentAnomalies(limit: Int): F[List[TrafficAnomaly]]

/** Represents the current state of network monitoring */
final case class NetworkStatus(
                                isRunning: Boolean,
                                monitoringSince: Option[Instant],
                                networkInterfaces: List[String],
                                anomalyCount: Int,
                                trafficStats: TrafficStats
                              )

/** Network traffic statistics */
final case class TrafficStats(
                               totalBytesSent: Long,
                               totalBytesReceived: Long,
                               connectionsPerMinute: Double,
                               activeConnections: Int
                             )

/** Network connection data */
final case class NetworkConnection(
                                    protocol: String,
                                    sourceIp: String,
                                    destinationIp: String,
                                    sourcePort: Int,
                                    destinationPort: Int,
                                    bytesSent: Long,
                                    bytesReceived: Long,
                                    timestamp: Instant = Instant.now()
                                  )

object NetworkMonitorService:
  def make[F[_]: Async: Logger](
                                 repository: SecurityEventRepository[F]
                               ): F[NetworkMonitorService[F]] =
    for
      hostInfo <- SystemInfo.getHostInfo[F]
      monitorRef <- Ref.of[F, Option[Fiber[F, Throwable, Unit]]](None)
      startTimeRef <- Ref.of[F, Option[Instant]](None)
      statsRef <- Ref.of[F, TrafficStats](
        TrafficStats(
          totalBytesSent = 0L,
          totalBytesReceived = 0L,
          connectionsPerMinute = 0.0,
          activeConnections = 0
        )
      )
      networkInterfaces <- NetworkUtils.getNetworkInterfaces[F]
    yield new NetworkMonitorServiceImpl[F](
      repository,
      hostInfo,
      monitorRef,
      startTimeRef,
      statsRef,
      networkInterfaces
    )

private class NetworkMonitorServiceImpl[F[_]: Async: Logger](
                                                              repository: SecurityEventRepository[F],
                                                              hostInfo: HostInfo,
                                                              monitorRef: Ref[F, Option[Fiber[F, Throwable, Unit]]],
                                                              startTimeRef: Ref[F, Option[Instant]],
                                                              statsRef: Ref[F, TrafficStats],
                                                              networkInterfaces: List[String]
                                                            ) extends NetworkMonitorService[F]:
  private implicit val logger: Logger[F] = Slf4jLogger.getLogger[F]

  // Known suspicious IP addresses and ports (would be more extensive in a real app)
  private val suspiciousIps: Set[String] = Set(
    "123.45.67.89",    // Known botnet C&C server
    "98.76.54.32",     // Known malware distribution server
    "192.168.1.200"    // Example internal suspicious host
  )

  private val suspiciousPorts: Set[Int] = Set(
    4444,  // Metasploit default listener
    8080,  // Common proxy port
    31337  // Historical "elite" hacker port
  )

  private val normalConnectionsPerMinThreshold = 100
  private val normalBytesPerSecThreshold = 1024 * 1024 * 10 // 10 MB/s

  def startMonitoring: F[Fiber[F, Throwable, Unit]] =
    for
      _ <- Logger[F].info("Starting network traffic monitoring")
      maybeExistingFiber <- monitorRef.get
      _ <- maybeExistingFiber.traverse_(_.cancel)
      now = Instant.now()
      _ <- startTimeRef.set(Some(now))
      fiber <- monitorNetworkTraffic.start
      _ <- monitorRef.set(Some(fiber))
    yield fiber

  def stopMonitoring: F[Unit] =
    for
      _ <- Logger[F].info("Stopping network traffic monitoring")
      maybeExistingFiber <- monitorRef.get
      _ <- maybeExistingFiber.traverse_(_.cancel)
      _ <- monitorRef.set(None)
      _ <- startTimeRef.set(None)
    yield ()

  def getCurrentStatus: F[NetworkStatus] =
    for
      maybeMonitor <- monitorRef.get
      startTime <- startTimeRef.get
      stats <- statsRef.get
      anomalyCount <- repository.count[TrafficAnomaly]
    yield NetworkStatus(
      isRunning = maybeMonitor.isDefined,
      monitoringSince = startTime,
      networkInterfaces = networkInterfaces,
      anomalyCount = anomalyCount,
      trafficStats = stats
    )

  def getRecentAnomalies(limit: Int): F[List[TrafficAnomaly]] =
    repository.getRecent[TrafficAnomaly](limit)

  private def monitorNetworkTraffic: F[Unit] =
    (for
      _ <- Stream.eval(Logger[F].info("Network monitoring started"))

      // Create a stream that emits every second for traffic polling
      _ <- Stream.fixedDelay[F](1.second)
        .evalMap(_ => pollNetworkTraffic)
        .handleErrorWith { error =>
          Stream.eval(Logger[F].error(error)("Error in network traffic monitoring"))
        }
    yield ()).compile.drain

  private def pollNetworkTraffic: F[Unit] =
    for
      // Simulate network traffic polling
      // In a real app, this would use platform-specific libraries to get actual traffic
      connections <- simulateNetworkConnections

      // Check for anomalies
      anomalies <- connections.traverse(detectAnomalies)
      validAnomalies = anomalies.flatten

      // Save detected anomalies
      _ <- validAnomalies.traverse(anomaly => repository.save(anomaly))

      // Log anomalies
      _ <- validAnomalies.traverse { anomaly =>
        Logger[F].warn(
          s"Traffic anomaly detected: ${anomaly.anomalyType} from ${anomaly.sourceIp}:${anomaly.sourcePort} " +
            s"to ${anomaly.destinationIp}:${anomaly.destinationPort} (${anomaly.details})"
        )
      }

      // Update traffic stats
      connectionCount = connections.size
      bytesSent = connections.map(_.bytesSent).sum
      bytesReceived = connections.map(_.bytesReceived).sum

      _ <- statsRef.update { stats =>
        stats.copy(
          totalBytesSent = stats.totalBytesSent + bytesSent,
          totalBytesReceived = stats.totalBytesReceived + bytesReceived,
          connectionsPerMinute = connectionCount * 60, // connections per minute based on current poll
          activeConnections = connectionCount
        )
      }
    yield ()

  private def simulateNetworkConnections: F[List[NetworkConnection]] =
    // In a real app, this would capture actual network traffic
    // For the simulation, we'll generate some realistic traffic patterns
    val r = new Random()
    val protocols = List("TCP", "UDP", "HTTP", "HTTPS", "DNS")
    val localIp = hostInfo.ipAddress

    // Generate random number of connections (5-20)
    val connectionCount = 5 + r.nextInt(16)

    val connections = List.fill(connectionCount) {
      val protocol = protocols(r.nextInt(protocols.size))
      val isOutbound = r.nextBoolean()

      val (sourceIp, destinationIp) = if (isOutbound) {
        (localIp, s"${10 + r.nextInt(240)}.${r.nextInt(256)}.${r.nextInt(256)}.${r.nextInt(256)}")
      } else {
        (s"${10 + r.nextInt(240)}.${r.nextInt(256)}.${r.nextInt(256)}.${r.nextInt(256)}", localIp)
      }

      val sourcePort = if (isOutbound) 1024 + r.nextInt(64511) else {
        // For inbound connections, typically they go to well-known service ports
        List(80, 443, 22, 53, 3389, 21, 25, 110)(r.nextInt(8))
      }

      val destPort = if (!isOutbound) 1024 + r.nextInt(64511) else {
        // For outbound connections, typically they go to well-known service ports
        List(80, 443, 22, 53, 3389, 21, 25, 110)(r.nextInt(8))
      }

      // Generate traffic volume - skewed to mostly small packets with occasional large transfers
      val trafficMultiplier = if (r.nextDouble() < 0.9) 1 else 100
      val bytesSent = r.nextInt(10000) * trafficMultiplier
      val bytesReceived = r.nextInt(10000) * trafficMultiplier

      // Occasionally inject a suspicious connection (about 5% of the time)
      val (finalSourceIp, finalDestIp, finalSourcePort, finalDestPort) =
        if (r.nextDouble() < 0.05) {
          if (r.nextBoolean()) {
            // Suspicious IP
            val suspIp = suspiciousIps.toList(r.nextInt(suspiciousIps.size))
            if (isOutbound)
              (localIp, suspIp, sourcePort, destPort)
            else
              (suspIp, localIp, sourcePort, destPort)
          } else {
            // Suspicious port
            val suspPort = suspiciousPorts.toList(r.nextInt(suspiciousPorts.size))
            if (isOutbound)
              (sourceIp, destinationIp, sourcePort, suspPort)
            else
              (sourceIp, destinationIp, suspPort, destPort)
          }
        } else {
          (sourceIp, destinationIp, sourcePort, destPort)
        }

      NetworkConnection(
        protocol = protocol,
        sourceIp = finalSourceIp,
        destinationIp = finalDestIp,
        sourcePort = finalSourcePort,
        destinationPort = finalDestPort,
        bytesSent = bytesSent,
        bytesReceived = bytesReceived
      )
    }

    connections.pure[F]

  private def detectAnomalies(conn: NetworkConnection): F[Option[TrafficAnomaly]] =
    val anomalyOpt = if (suspiciousIps.contains(conn.sourceIp) || suspiciousIps.contains(conn.destinationIp)) {
      // Suspicious IP address detected
      Some(
        TrafficAnomaly(
          severity = Severity.High,
          source = "NetworkMonitor",
          details = "Communication with known malicious IP address",
          protocol = conn.protocol,
          sourceIp = conn.sourceIp,
          destinationIp = conn.destinationIp,
          sourcePort = conn.sourcePort,
          destinationPort = conn.destinationPort,
          bytesSent = conn.bytesSent,
          bytesReceived = conn.bytesReceived,
          anomalyType = AnomalyType.SuspiciousConnection
        )
      )
    } else if (suspiciousPorts.contains(conn.sourcePort) || suspiciousPorts.contains(conn.destinationPort)) {
      // Suspicious port detected
      Some(
        TrafficAnomaly(
          severity = Severity.Medium,
          source = "NetworkMonitor",
          details = "Communication on suspicious port",
          protocol = conn.protocol,
          sourceIp = conn.sourceIp,
          destinationIp = conn.destinationIp,
          sourcePort = conn.sourcePort,
          destinationPort = conn.destinationPort,
          bytesSent = conn.bytesSent,
          bytesReceived = conn.bytesReceived,
          anomalyType = AnomalyType.SuspiciousConnection
        )
      )
    } else if (conn.bytesSent > normalBytesPerSecThreshold) {
      // Potential data exfiltration
      Some(
        TrafficAnomaly(
          severity = Severity.High,
          source = "NetworkMonitor",
          details = s"Large outbound data transfer: ${conn.bytesSent / 1024 / 1024} MB",
          protocol = conn.protocol,
          sourceIp = conn.sourceIp,
          destinationIp = conn.destinationIp,
          sourcePort = conn.sourcePort,
          destinationPort = conn.destinationPort,
          bytesSent = conn.bytesSent,
          bytesReceived = conn.bytesReceived,
          anomalyType = AnomalyType.DataExfiltration
        )
      )
    } else if (conn.protocol == "TCP" && conn.destinationPort == 22 &&
      conn.sourceIp.startsWith("192.168.") && conn.bytesSent < 1000 &&
      Random().nextDouble() < 0.3) {
      // Simulate occasional detection of brute force SSH login attempts
      Some(
        TrafficAnomaly(
          severity = Severity.Medium,
          source = "NetworkMonitor",
          details = "Potential SSH brute force attempt",
          protocol = conn.protocol,
          sourceIp = conn.sourceIp,
          destinationIp = conn.destinationIp,
          sourcePort = conn.sourcePort,
          destinationPort = conn.destinationPort,
          bytesSent = conn.bytesSent,
          bytesReceived = conn.bytesReceived,
          anomalyType = AnomalyType.BruteForce
        )
      )
    } else {
      None
    }

    anomalyOpt.pure[F]