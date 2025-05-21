package com.endsec.services

import cats.effect.*
import cats.syntax.all.*
import fs2.Stream
import fs2.io.file.{Files, Path}
import org.typelevel.log4cats.Logger

import com.endsec.domain.*
import com.endsec.repositories.SecurityEventRepository
import com.endsec.utils.SystemInfo

import java.time.Instant
import java.util.UUID
import scala.concurrent.duration.*

/** Service for scanning and detecting viruses */
trait VirusScanService[F[_]]:
  def scanFile(path: Path): F[Option[VirusDetection]]
  def scanDirectory(dir: Path, recursive: Boolean): Stream[F, VirusDetection]
  def fullSystemScan: F[ScanResult[VirusDetection]]
  def quickScan: F[ScanResult[VirusDetection]]

object VirusScanService:
  def make[F[_]: Async: Files: Logger](
                                        repository: SecurityEventRepository[F]
                                      ): F[VirusScanService[F]] =
    SystemInfo.getHostInfo[F].map { hostInfo =>
      new VirusScanServiceImpl[F](repository, hostInfo)
    }

private class VirusScanServiceImpl[F[_]: Async: Files: Logger](
                                                                repository: SecurityEventRepository[F],
                                                                hostInfo: HostInfo
                                                              ) extends VirusScanService[F]:

  // Virus signatures database (in a real app would be much more sophisticated)
  private val virusSignatures: Map[String, String] = Map(
    "JeKWmfxT8C" -> "Trojan.Generic",
    "xMalZp98Kw" -> "Worm.Variants",
    "tRPnvTY76q" -> "Backdoor.Access",
    "KpQwFkL47R" -> "Ransomware.Crypto"
  )

  def scanFile(path: Path): F[Option[VirusDetection]] =
    for
      exists <- Files[F].exists(path)
      result <- if exists then
        Files[F].readAll(path)
          .through(fs2.text.utf8.decode)
          .compile
          .string
          .flatMap(checkForVirus(path, _))
      else
        Logger[F].warn(s"File not found: $path") *>
          Option.empty[VirusDetection].pure[F]
    yield result

  def scanDirectory(dir: Path, recursive: Boolean): Stream[F, VirusDetection] =
    (if recursive then Files[F].walk(dir) else Files[F].list(dir))
      .flatMap { path =>
        Stream.eval(Files[F].isRegularFile(path)).flatMap { regular =>
          if regular then Stream.eval(scanFile(path)).flatMap(Stream.fromOption(_))
          else Stream.empty
        }
      }

  def fullSystemScan: F[ScanResult[VirusDetection]] =
    val scanId = UUID.randomUUID()
    val startTime = Instant.now()

    for
      _ <- Logger[F].info(s"Starting full system virus scan with ID: $scanId")

      rootPaths <- if hostInfo.os.toLowerCase.contains("windows") then
        List(Path("C:\\")).pure[F]
      else
        List(Path("/")).pure[F]

      detections <- rootPaths
        .map(scanDirectory(_, recursive = true))
        .reduce(_ ++ _)
        .compile
        .toList

      _ <- detections.traverse(detection => repository.save(detection))
      _ <- Logger[F].info(s"Full system scan completed. Found ${detections.size} threats.")

      endTime = Instant.now()
    yield ScanResult(
      scanId = scanId,
      scanStartTime = startTime,
      scanEndTime = endTime,
      scanType = ScanType.VirusScan,
      events = detections,
      hostInfo = hostInfo
    )

  def quickScan: F[ScanResult[VirusDetection]] =
    val scanId = UUID.randomUUID()
    val startTime = Instant.now()

    for
      _ <- Logger[F].info(s"Starting quick virus scan with ID: $scanId")

      commonPaths <- if hostInfo.os.toLowerCase.contains("windows") then
        List(
          Path("C:\\Users"),
          Path("C:\\Program Files"),
          Path("C:\\Windows\\Temp")
        ).pure[F]
      else
        List(
          Path("/home"),
          Path("/tmp"),
          Path("/var/tmp")
        ).pure[F]

      detections <- commonPaths
        .map(scanDirectory(_, recursive = false))
        .reduce(_ ++ _)
        .compile
        .toList

      _ <- detections.traverse(detection => repository.save(detection))
      _ <- Logger[F].info(s"Quick scan completed. Found ${detections.size} threats.")

      endTime = Instant.now()
    yield ScanResult(
      scanId = scanId,
      scanStartTime = startTime,
      scanEndTime = endTime,
      scanType = ScanType.VirusScan,
      events = detections,
      hostInfo = hostInfo
    )

  private def checkForVirus(path: Path, content: String): F[Option[VirusDetection]] =
    // Simple virus signature checking (in a real app, this would be more sophisticated)
    val foundSignature = virusSignatures.find { case (signature, _) =>
      content.contains(signature)
    }

    foundSignature match
      case Some((signature, virusName)) =>
        val detection = VirusDetection(
          severity = Severity.High,
          source = "VirusScan",
          details = s"Detected virus: $virusName",
          filePath = path.toString,
          virusSignature = signature,
          quarantined = false
        )
        Logger[F].warn(s"Virus detected in ${path}: $virusName") *>
          repository.save(detection) *>
          detection.some.pure[F]

      case None =>
        Option.empty[VirusDetection].pure[F]