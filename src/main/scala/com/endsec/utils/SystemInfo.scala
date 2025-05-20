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
    Sync[F].delay(InetAddress.getLocalHost.getHostName)
      .handleErrorWith { e =>
        Logger[F].warn(s"Failed to get hostname: ${e.getMessage}") *>
          Sync[F].pure("unknown-host")
      }

  private def getIpAddress[F[_]: Sync: Logger]: F[String] =
    Sync[F].delay(InetAddress.getLocalHost.getHostAddress)
      .handleErrorWith { e =>
        Logger[F].warn(s"Failed to get IP address: ${e.getMessage}") *>
          Sync[F].pure("127.0.0.1")
      }

  private def getOperatingSystem[F[_]: Sync: Logger]: F[String] =
    Sync[F].delay(System.getProperty("os.name"))
      .handleErrorWith { e =>
        Logger[F].warn(s"Failed to get OS: ${e.getMessage}") *>
          Sync[F].pure("Unknown OS")
      }

  private def getOsVersion[F[_]: Sync: Logger]: F[String] =
    Sync[F].delay(System.getProperty("os.version"))
      .handleErrorWith { e =>
        Logger[F].warn(s"Failed to get OS version: ${e.getMessage}") *>
          Sync[F].pure("Unknown Version")
      }

  private def getCpuArchitecture[F[_]: Sync: Logger]: F[String] =
    Sync[F].delay(System.getProperty("os.arch"))
      .handleErrorWith { e =>
        Logger[F].warn(s"Failed to get CPU architecture: ${e.getMessage}") *>
          Sync[F].pure("Unknown Architecture")
      }

/** Utilities for process execution */
object ProcessUtils:
  def exec[F[_]: Sync: Logger](command: List[String]): F[String] =
    implicit val logger: Logger[F] = Slf4jLogger.getLogger[F]

    Sync[F].delay {
      import  scala.sys.process._
      val output = command.!!
      output
    }.handleErrorWith { e =>
      Logger[F].warn(s"Failed to execute command ${command.mkString(" ")}: ${e.getMessage}") *>
        Sync[F].pure("Command execution failed")
    }

/** Utilities for network operations */
object NetworkUtils:
  def getNetworkInterfaces[F[_]: Sync: Logger]: F[List[String]] =
    implicit val logger: Logger[F] = Slf4jLogger.getLogger[F]

    Sync[F].delay {
      NetworkInterface.getNetworkInterfaces.asScala.toList
        .flatMap { iface =>
          if iface.isUp && !iface.isLoopback && !iface.isVirtual then
            Some(iface.getName)
          else
            None
        }
    }.handleErrorWith { e =>
          Logger[F].warn(s"Failed to get network interfaces: ${e.getMessage}") *>
            Sync[F].pure(List("eth0")) // Fallback to default
    }