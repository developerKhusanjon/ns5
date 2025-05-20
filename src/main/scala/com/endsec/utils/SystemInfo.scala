package com.endsec.utils

import cats.effect.*
import cats.syntax.all.*
import org.typelevel.log4cats.Logger
import org.typelevel.log4cats.slf4j.Slf4jLogger

import com.endsec.domain.HostInfo

import java.net.{InetAddress, NetworkInterface}
import scala.util.control.NonFatal
import scala.jdk.CollectionConverters.*

/** Utilities for getting system information */
object SystemInfo:
  def getHostInfo[F[_]: Sync: Logger]: F[HostInfo] =
    implicit val logger: Logger[F] = Slf4jLogger.getLogger[F]

    for
      hostname <- getHostname[F]
      ipAddress <- getIpAddress[F]
      os <- getOperatingSystem[F]
      osVersion <- getOsVersion[F]
      cpuArchitecture <- getCpuArchitecture[F]
      hostId = java.util.UUID.nameUUIDFromBytes(s"$hostname-$ipAddress-$os".getBytes).toString
    yield HostInfo(
      hostId = hostId,
      hostname = hostname,
      ipAddress = ipAddress,
      os = os,
      osVersion = osVersion,
      cpuArchitecture = cpuArchitecture
    )

  private def getHostname[F[_]: Sync: Logger]: F[String] =
    Sync[F].delay {
      try
        InetAddress.getLocalHost.getHostName
      catch
        case NonFatal(e) =>
          Logger[F].warn(s"Failed to get hostname: ${e.getMessage}").unsafeRunSync()
          "unknown-host"
    }

  private def getIpAddress[F[_]: Sync: Logger]: F[String] =
    Sync[F].delay {
      try
        InetAddress.getLocalHost.getHostAddress
      catch
        case NonFatal(e) =>
          Logger[F].warn(s"Failed to get IP address: ${e.getMessage}").unsafeRunSync()
          "127.0.0.1"
    }

  private def getOperatingSystem[F[_]: Sync: Logger]: F[String] =
    Sync[F].delay {
      try
        System.getProperty("os.name")
      catch
        case NonFatal(e) =>
          Logger[F].warn(s"Failed to get OS: ${e.getMessage}").unsafeRunSync()
          "Unknown OS"
    }

  private def getOsVersion[F[_]: Sync: Logger]: F[String] =
    Sync[F].delay {
      try
        System.getProperty("os.version")
      catch
        case NonFatal(e) =>
          Logger[F].warn(s"Failed to get OS version: ${e.getMessage}").unsafeRunSync()
          "Unknown Version"
    }

  private def getCpuArchitecture[F[_]: Sync: Logger]: F[String] =
    Sync[F].delay {
      try
        System.getProperty("os.arch")
      catch
        case NonFatal(e) =>
          Logger[F].warn(s"Failed to get CPU architecture: ${e.getMessage}").unsafeRunSync()
          "Unknown Architecture"
    }

/** Utilities for process execution */
object ProcessUtils:
  def exec[F[_]: Sync: Logger](command: List[String]): F[String] =
    implicit val logger: Logger[F] = Slf4jLogger.getLogger[F]

    Sync[F].delay {
      try
        import scala.sys.process._
        val output = command.!!
        output
      catch
        case NonFatal(e) =>
          Logger[F].warn(s"Failed to execute command ${command.mkString(" ")}: ${e.getMessage}").unsafeRunSync()
          "Command execution failed"
    }

/** Utilities for network operations */
object NetworkUtils:
  def getNetworkInterfaces[F[_]: Sync: Logger]: F[List[String]] =
    implicit val logger: Logger[F] = Slf4jLogger.getLogger[F]

    Sync[F].delay {
      try
        val interfaces = NetworkInterface.getNetworkInterfaces.asScala.toList
        interfaces.flatMap { iface =>
          if iface.isUp && !iface.isLoopback && !iface.isVirtual then
            Some(iface.getName)
          else
            None
        }
      catch
        case NonFatal(e) =>
          Logger[F].warn(s"Failed to get network interfaces: ${e.getMessage}").unsafeRunSync()
          List("eth0") // Fallback to a default name
    }