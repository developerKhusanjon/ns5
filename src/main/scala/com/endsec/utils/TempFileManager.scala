package com.endsec.utils

import cats.effect.*
import cats.syntax.all.*
import fs2.{Stream, io}
import fs2.io.file.{Files, Path}
import org.typelevel.log4cats.Logger

import com.endsec.errors.*

import java.io.IOException
import java.util.UUID
import scala.concurrent.duration.*

/**
 * Manager for handling temporary files with automatic cleanup
 */
trait TempFileManager[F[_]]:
  /**
   * Create a temporary file that will be deleted when the returned Resource is closed
   *
   * @param prefix Prefix for the file name
   * @param suffix Suffix for the file name (file extension)
   * @param content Optional content to write to the file
   * @return Resource managing the temporary file
   */
  def createTempFile(
                      prefix: String,
                      suffix: String,
                      content: Option[Stream[F, Byte]] = None
                    ): Resource[F, Path]

  /**
   * Create a temporary directory that will be deleted when the returned Resource is closed
   *
   * @param prefix Prefix for the directory name
   * @return Resource managing the temporary directory
   */
  def createTempDirectory(prefix: String): Resource[F, Path]

  /**
   * Create a temporary copy of a file that will be deleted when the returned Resource is closed
   *
   * @param sourcePath Path to the source file
   * @param prefix Prefix for the temporary file name
   * @return Resource managing the temporary file copy
   */
  def createTempCopy(sourcePath: Path, prefix: String): Resource[F, Path]

  /**
   * Create a secure working area for scanning potentially malicious files
   *
   * @param prefix Prefix for the directory name
   * @return Resource managing the temporary workspace
   */
  def createScanWorkspace(prefix: String = "scan_"): Resource[F, Path]

object TempFileManager:
  /**
   * Create a new TempFileManager
   */
  def make[F[_]: Async: Files: Logger]: F[TempFileManager[F]] =
    Async[F].delay(new TempFileManagerImpl[F])

private class TempFileManagerImpl[F[_]: Async: Files: Logger] extends TempFileManager[F]:
  private val logger = org.typelevel.log4cats.slf4j.Slf4jLogger.getLoggerFromClass[F](classOf[TempFileManagerImpl[F]])

  /**
   * Create a temporary file that will be deleted when the returned Resource is closed
   */
  def createTempFile(
                      prefix: String,
                      suffix: String,
                      content: Option[Stream[F, Byte]] = None
                    ): Resource[F, Path] =
    Resource.make(
      acquire = Files[F].createTempFile(Some(prefix), Some(suffix)).flatMap { path =>
        content match
          case Some(data) =>
            data.through(Files[F].writeAll(path)).compile.drain.as(path)
          case None =>
            path.pure[F]
      }
    )(
      release = path =>
        Files[F].exists(path).flatMap { exists =>
          if exists then
            Files[F].delete(path).handleErrorWith { error =>
              logger.warn(error)(s"Failed to delete temporary file: $path")
            }
          else
            Async[F].unit
        }
    )

  /**
   * Create a temporary directory that will be deleted when the returned Resource is closed
   */
  def createTempDirectory(prefix: String): Resource[F, Path] =
    Resource.make(
      acquire = Files[F].createTempDirectory(Some(prefix))
    )(
      release = path =>
        deleteRecursively(path).handleErrorWith { error =>
          logger.warn(error)(s"Failed to delete temporary directory: $path")
        }
    )

  /**
   * Create a temporary copy of a file that will be deleted when the returned Resource is closed
   */
  def createTempCopy(sourcePath: Path, prefix: String): Resource[F, Path] =
    Resource.eval(Files[F].exists(sourcePath)).flatMap { exists =>
      if !exists then
        Resource.eval(
          Async[F].raiseError[Path](
            StorageError(
              message = s"Source file not found: $sourcePath",
              errorCode = FileSystemErrorUtils.ErrorCodes.FileNotFound,
              operation = "creating temporary copy",
              details = Some(s"The source file does not exist")
            )
          )
        )
      else
        for
          tempPath <- createTempFile(prefix, s".${getFileExtension(sourcePath)}")
          _ <- Resource.eval(
            FileSystemErrorUtils.safeMoveFile(sourcePath, tempPath, overwrite = true)
              .handleErrorWith { error =>
                Async[F].raiseError(
                  StorageError(
                    message = s"Failed to copy file: $error",
                    cause = Some(error),
                    errorCode = FileSystemErrorUtils.ErrorCodes.IoError,
                    operation = "creating temporary copy",
                    details = Some(s"Error copying from $sourcePath to $tempPath")
                  )
                )
              }
          )
        yield tempPath
    }

  /**
   * Create a secure working area for scanning potentially malicious files
   */
  def createScanWorkspace(prefix: String = "scan_"): Resource[F, Path] =
    // Create a timestamped unique workspace
    val timestamp = java.time.Instant.now().toEpochMilli
    val uniqueId = UUID.randomUUID().toString.take(8)
    val workspacePrefix = s"${prefix}${timestamp}_${uniqueId}"

    createTempDirectory(workspacePrefix)

  /**
   * Recursively delete a directory and all its contents
   */
  private def deleteRecursively(path: Path): F[Unit] =
    Files[F].exists(path).flatMap { exists =>
      if !exists then
        Async[F].unit
      else
        Files[F].isDirectory(path).flatMap { isDir =>
          if isDir then
            // Delete all directory contents first
            Files[F].list(path)
              .evalMap(deleteRecursively)
              .compile
              .drain
              .flatMap(_ => Files[F].delete(path))
          else
            // Delete the file
            Files[F].delete(path)
        }
    }

  /**
   * Get the file extension from a path
   */
  private def getFileExtension(path: Path): String =
    val fileName = path.fileName.toString
    fileName.lastIndexOf('.') match
      case -1 => ""  // No extension
      case i => fileName.substring(i + 1)