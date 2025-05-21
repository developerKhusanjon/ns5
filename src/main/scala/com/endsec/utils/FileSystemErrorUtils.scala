package com.endsec.utils

import cats.effect.*
import cats.syntax.all.*
import fs2.{Stream, io, text}
import fs2.io.file.{Files, Path, NoSuchFileException, FileAlreadyExistsException, PosixError}
import org.typelevel.log4cats.Logger

import com.endsec.errors.*
import com.endsec.utils.ResilienceUtils
import com.endsec.utils.RetryStrategies

import java.io.IOException
import java.nio.file.{AccessDeniedException, FileSystemException}
import scala.concurrent.duration.*

/**
 * Utilities for handling and recovering from filesystem errors
 */
object FileSystemErrorUtils:
  /**
   * Error codes for filesystem operations
   */
  object ErrorCodes:
    val FileNotFound = AppError.ErrorCodePrefix.Storage + "-101"
    val AccessDenied = AppError.ErrorCodePrefix.Storage + "-102"
    val FileAlreadyExists = AppError.ErrorCodePrefix.Storage + "-103"
    val FileLocked = AppError.ErrorCodePrefix.Storage + "-104"
    val DiskFull = AppError.ErrorCodePrefix.Storage + "-105"
    val IoError = AppError.ErrorCodePrefix.Storage + "-106"
    val ReadError = AppError.ErrorCodePrefix.Storage + "-107"
    val WriteError = AppError.ErrorCodePrefix.Storage + "-108"
    val DirectoryError = AppError.ErrorCodePrefix.Storage + "-109"

  /**
   * Convert a filesystem exception to a specific StorageError
   *
   * @param error The filesystem exception
   * @param operation String describing the operation that caused the error
   * @return An appropriate StorageError
   */
  def handleFsException(error: Throwable, operation: String): StorageError =
    error match
      case e: NoSuchFileException =>
        StorageError(
          message = s"File not found: ${e.getFile}",
          cause = Some(e),
          errorCode = ErrorCodes.FileNotFound,
          operation = operation,
          details = Some(s"The requested file ${e.getFile} does not exist.")
        )
      case e: AccessDeniedException =>
        StorageError(
          message = s"Access denied: ${e.getFile}",
          cause = Some(e),
          errorCode = ErrorCodes.AccessDenied,
          operation = operation,
          details = Some(s"Permission denied when accessing ${e.getFile}")
        )
      case e: FileAlreadyExistsException =>
        StorageError(
          message = s"File already exists: ${e.getMessage}",
          cause = Some(e),
          errorCode = ErrorCodes.FileAlreadyExists,
          operation = operation,
          details = Some(s"Cannot create file because it already exists")
        )
      case e: PosixError =>
        StorageError(
          message = s"Filesystem error: ${e.getMessage}",
          cause = Some(e),
          errorCode = ErrorCodes.IoError,
          operation = operation,
          details = Some(s"POSIX error code: ${e.errorCode}")
        )
      case e: FileSystemException if e.getReason != null && e.getReason.contains("locked") =>
        StorageError(
          message = s"File is locked: ${e.getFile}",
          cause = Some(e),
          errorCode = ErrorCodes.FileLocked,
          operation = operation,
          details = Some(s"The file is currently locked by another process")
        )
      case e: FileSystemException if e.getReason != null && e.getReason.contains("space") =>
        StorageError(
          message = s"Disk is full: ${e.getFile}",
          cause = Some(e),
          errorCode = ErrorCodes.DiskFull,
          operation = operation,
          details = Some(s"Not enough space left on device")
        )
      case e: IOException =>
        StorageError(
          message = s"I/O error during $operation: ${e.getMessage}",
          cause = Some(e),
          errorCode = ErrorCodes.IoError,
          operation = operation,
          details = None
        )
      case e =>
        StorageError(
          message = s"Unexpected error during $operation: ${e.getMessage}",
          cause = Some(e),
          errorCode = AppError.ErrorCodePrefix.Storage + "-999",
          operation = operation,
          details = None
        )

  /**
   * Safely read a file with error handling and resilience
   *
   * @param path Path to the file to read
   * @param maxRetries Maximum number of retries for the operation
   * @return Stream of bytes from the file or raises an appropriate StorageError
   */
  def safeReadFile[F[_]: Async: Files: Logger](
                                                path: Path,
                                                maxRetries: Int = 3
                                              ): Stream[F, Byte] =
    Stream.eval(Files[F].exists(path)).flatMap { exists =>
      if exists then
        Files[F].readAll(path)
          .handleErrorWith { error =>
            Stream.eval(
              Logger[F].error(error)(s"Error reading file $path") *>
                Async[F].raiseError(handleFsException(error, s"reading file $path"))
            ).drain
          }
      else
        Stream.eval(
          Logger[F].warn(s"File not found: $path") *>
            Async[F].raiseError(
              StorageError(
                message = s"File not found: $path",
                errorCode = ErrorCodes.FileNotFound,
                operation = s"reading file $path",
                details = Some(s"The requested file does not exist")
              )
            )
        ).drain
    }

  /**
   * Safely write data to a file with error handling and resilience
   *
   * @param path Path to the file to write
   * @param data Stream of bytes to write
   * @param overwrite Whether to overwrite an existing file
   * @param maxRetries Maximum number of retries for the operation
   * @return Unit or raises an appropriate StorageError
   */
  def safeWriteFile[F[_]: Async: Files: Logger](
                                                 path: Path,
                                                 data: Stream[F, Byte],
                                                 overwrite: Boolean = false,
                                                 maxRetries: Int = 3
                                               ): F[Unit] =
    val writeOperation = Files[F].exists(path).flatMap { exists =>
      if exists && !overwrite then
        Async[F].raiseError(
          StorageError(
            message = s"File already exists: $path",
            errorCode = ErrorCodes.FileAlreadyExists,
            operation = s"writing file $path",
            details = Some(s"File already exists and overwrite is set to false")
          )
        )
      else
        // Ensure parent directories exist
        val createParentDirs = ensureDirectoryExists(path.parent)

        createParentDirs >>
          data.through(Files[F].writeAll(path)).compile.drain
    }

    // Apply retry strategy
    ResilienceUtils.retryWithBackoff(
      writeOperation,
      maxRetries = maxRetries,
      initialDelay = 100.millis,
      maxDelay = 1.second,
      shouldRetry = error => error match
        case _: IOException => true
        case _: FileSystemException => true
        case _ => false
    ).handleErrorWith { error =>
      Logger[F].error(error)(s"Failed to write file $path after retries") *>
        Async[F].raiseError(handleFsException(error, s"writing file $path"))
    }

  /**
   * Ensure a directory exists, creating it if necessary
   *
   * @param dirPath Path to the directory
   * @return Unit or raises an appropriate StorageError
   */
  def ensureDirectoryExists[F[_]: Async: Files: Logger](dirPath: Path): F[Unit] =
    Files[F].exists(dirPath).flatMap { exists =>
      if exists then
        Files[F].isDirectory(dirPath).flatMap { isDir =>
          if isDir then
            Async[F].unit
          else
            Async[F].raiseError(
              StorageError(
                message = s"Path exists but is not a directory: $dirPath",
                errorCode = ErrorCodes.DirectoryError,
                operation = s"creating directory $dirPath",
                details = Some(s"Cannot create directory because a file with the same name exists")
              )
            )
        }
      else
        Files[F].createDirectories(dirPath)
          .handleErrorWith { error =>
            Logger[F].error(error)(s"Error creating directory $dirPath") *>
              Async[F].raiseError(handleFsException(error, s"creating directory $dirPath"))
          }
    }

  /**
   * Safely delete a file with error handling
   *
   * @param path Path to the file to delete
   * @param mustExist Whether the file must exist (raises an error if not)
   * @return True if the file was deleted, false if it didn't exist and mustExist is false
   */
  def safeDeleteFile[F[_]: Async: Files: Logger](
                                                  path: Path,
                                                  mustExist: Boolean = true
                                                ): F[Boolean] =
    Files[F].exists(path).flatMap { exists =>
      if exists then
        Files[F].delete(path)
          .as(true)
          .handleErrorWith { error =>
            Logger[F].error(error)(s"Error deleting file $path") *>
              Async[F].raiseError(handleFsException(error, s"deleting file $path"))
          }
      else if mustExist then
        Async[F].raiseError(
          StorageError(
            message = s"File not found: $path",
            errorCode = ErrorCodes.FileNotFound,
            operation = s"deleting file $path",
            details = Some(s"The file to delete does not exist")
          )
        )
      else
        false.pure[F]
    }

  /**
   * Safely move a file with error handling and resilience
   *
   * @param source Source path
   * @param target Target path
   * @param overwrite Whether to overwrite the target if it exists
   * @param maxRetries Maximum number of retries for the operation
   * @return Unit or raises an appropriate StorageError
   */
  def safeMoveFile[F[_]: Async: Files: Logger](
                                                source: Path,
                                                target: Path,
                                                overwrite: Boolean = false,
                                                maxRetries: Int = 3
                                              ): F[Unit] =
    val moveOperation = for
      sourceExists <- Files[F].exists(source)
      _ <- if !sourceExists then
        Async[F].raiseError(
          StorageError(
            message = s"Source file not found: $source",
            errorCode = ErrorCodes.FileNotFound,
            operation = s"moving file from $source to $target",
            details = Some(s"The source file does not exist")
          )
        )
      else
        Async[F].unit

      targetExists <- Files[F].exists(target)
      _ <- if targetExists && !overwrite then
        Async[F].raiseError(
          StorageError(
            message = s"Target file already exists: $target",
            errorCode = ErrorCodes.FileAlreadyExists,
            operation = s"moving file from $source to $target",
            details = Some(s"Target file already exists and overwrite is set to false")
          )
        )
      else if targetExists then
        Files[F].delete(target)
      else
        Async[F].unit

      _ <- ensureDirectoryExists(target.parent)
      _ <- Files[F].move(source, target)
    yield ()

    // Apply retry strategy
    ResilienceUtils.retryWithBackoff(
      moveOperation,
      maxRetries = maxRetries,
      initialDelay = 100.millis,
      maxDelay = 1.second,
      shouldRetry = error => error match
        case _: IOException => true
        case _: FileSystemException => true
        case _ => false
    ).handleErrorWith { error =>
      Logger[F].error(error)(s"Failed to move file from $source to $target after retries") *>
        Async[F].raiseError(handleFsException(error, s"moving file from $source to $target"))
    }

  /**
   * Safely read a file to a string with error handling
   *
   * @param path Path to the file to read
   * @param charset Character set (default UTF-8)
   * @return String content of the file or raises an appropriate StorageError
   */
  def safeReadString[F[_]: Async: Files: Logger](
                                                  path: Path,
                                                  charset: java.nio.charset.Charset = java.nio.charset.StandardCharsets.UTF_8
                                                ): F[String] =
    safeReadFile(path)
      .through(text.decode(charset))
      .compile
      .string
      .handleErrorWith { error =>
        Logger[F].error(error)(s"Error reading file as string: $path") *>
          Async[F].raiseError(handleFsException(error, s"reading file as string $path"))
      }

  /**
   * Safely write a string to a file with error handling
   *
   * @param path Path to the file to write
   * @param content String content to write
   * @param charset Character set (default UTF-8)
   * @param overwrite Whether to overwrite an existing file
   * @return Unit or raises an appropriate StorageError
   */
  def safeWriteString[F[_]: Async: Files: Logger](
                                                   path: Path,
                                                   content: String,
                                                   charset: java.nio.charset.Charset = java.nio.charset.StandardCharsets.UTF_8,
                                                   overwrite: Boolean = false
                                                 ): F[Unit] =
    val stringStream = Stream.emit(content).through(text.encode(charset))
    safeWriteFile(path, stringStream, overwrite)

  /**
   * Create a temporary directory with error handling
   *
   * @param prefix Prefix for the directory name
   * @return Path to the created temporary directory
   */
  def createTempDirectory[F[_]: Async: Files: Logger](
                                                       prefix: String
                                                     ): F[Path] =
    Files[F].createTempDirectory(Some(prefix))
      .handleErrorWith { error =>
        Logger[F].error(error)(s"Error creating temporary directory with prefix $prefix") *>
          Async[F].raiseError(handleFsException(error, s"creating temporary directory with prefix $prefix"))
      }

  /**
   * Create a quarantine location for isolating malicious files
   *
   * @param baseDir Base directory for quarantine
   * @return Path to the quarantine directory
   */
  def createQuarantineLocation[F[_]: Async: Files: Logger](
                                                            baseDir: Path
                                                          ): F[Path] =
    val quarantineDir = baseDir / "quarantine"
    ensureDirectoryExists(quarantineDir).as(quarantineDir)

  /**
   * Move a file to quarantine
   *
   * @param filePath Path to the file to quarantine
   * @param quarantineDir Quarantine directory
   * @return Path to the quarantined file
   */
  def moveToQuarantine[F[_]: Async: Files: Logger](
                                                    filePath: Path,
                                                    quarantineDir: Path
                                                  ): F[Path] =
    val fileName = filePath.fileName.toString
    val timestamp = java.time.Instant.now().toEpochMilli
    val quarantinedFilePath = quarantineDir / s"${timestamp}_${fileName}"

    safeMoveFile(filePath, quarantinedFilePath, overwrite = false)
      .as(quarantinedFilePath)