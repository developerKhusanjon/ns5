package com.endsec.monitoring

import cats.effect.*
import cats.syntax.all.*
import fs2.{Stream, Pipe}
import fs2.io.file.{Files, Path, WatchEvent}
import org.typelevel.log4cats.Logger
import org.typelevel.log4cats.slf4j.Slf4jLogger

import com.endsec.domain.*
import com.endsec.services.VirusScanService
import com.endsec.repositories.SecurityEventRepository
import com.endsec.utils.{FileSystemErrorUtils, SystemInfo}

import java.nio.file.{StandardWatchEventKinds => EventKind}
import java.time.Instant
import java.util.UUID
import scala.concurrent.duration.*

/**
 * Core service for monitoring filesystem activities for suspicious changes
 */
trait FileSystemMonitoring[F[_]]:
  /**
   * Start monitoring a directory for suspicious file activities 
   *
   * @param directory Path to monitor
   * @param recursive Whether to monitor subdirectories recursively
   * @param fileFilter Optional predicate to filter which files to monitor
   * @return Stream that emits events when suspicious activities are detected
   */
  def monitorDirectory(
                        directory: Path,
                        recursive: Boolean,
                        fileFilter: Path => Boolean = _ => true
                      ): Stream[F, FileSystemEvent]

  /**
   * Set up monitoring on system directories considered high risk
   *
   * @return Stream that emits events when suspicious activities are detected
   */
  def monitorHighRiskDirectories: Stream[F, FileSystemEvent]

  /**
   * Respond to a suspicious file event
   *
   * @param event The filesystem event to respond to
   * @return Result of the response action
   */
  def handleSuspiciousFile(event: FileSystemEvent): F[ResponseAction]

  /**
   * Get information about currently monitored directories
   *
   * @return List of monitoring configurations
   */
  def getMonitoringStatus: F[List[MonitoringInfo]]

object FileSystemMonitoring:
  /**
   * Create a new FileSystemMonitoring service
   */
  def make[F[_]: Async: Files: Logger](
                                        repository: SecurityEventRepository[F],
                                        virusScanService: VirusScanService[F]
                                      ): F[FileSystemMonitoring[F]] =
    SystemInfo.getHostInfo[F].flatMap { hostInfo =>
      for
        logger <- Slf4jLogger.create[F]
        // Configuration for dangerous extensions/patterns
        dangerousExtensions = Set(
          "exe", "dll", "bat", "cmd", "ps1", "vbs",
          "js", "jar", "sh", "py", "rb", "php"
        )
        // Configuration for high-risk system directories
        highRiskDirs = if hostInfo.os.toLowerCase.contains("windows") then
          List(
            Path("C:\\Windows\\System32"),
            Path("C:\\Windows\\Tasks"),
            Path("C:\\Windows\\Temp"),
            Path("C:\\Users\\Public"),
            Path("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
          )
        else
          List(
            Path("/etc"),
            Path("/tmp"),
            Path("/var/tmp"),
            Path("/var/www"),
            Path("/bin"),
            Path("/usr/bin"),
            Path("/home")
          )
      yield new FileSystemMonitoringImpl[F](
        repository,
        virusScanService,
        dangerousExtensions,
        highRiskDirs,
        hostInfo,
        logger
      )
    }

private class FileSystemMonitoringImpl[F[_]: Async: Files: Logger](
                                                                    repository: SecurityEventRepository[F],
                                                                    virusScanService: VirusScanService[F],
                                                                    dangerousExtensions: Set[String],
                                                                    highRiskDirectories: List[Path],
                                                                    hostInfo: HostInfo,
                                                                    logger: Logger[F]
                                                                  ) extends FileSystemMonitoring[F]:

  // Configuration for how often to poll directories that don't support native watching
  private val defaultPollingInterval: FiniteDuration = 5.seconds

  // Keep track of currently monitored directories
  private var activeMonitoring: List[MonitoringInfo] = List.empty

  /**
   * Monitor a directory for suspicious file activities
   */
  def monitorDirectory(
                        directory: Path,
                        recursive: Boolean,
                        fileFilter: Path => Boolean = _ => true
                      ): Stream[F, FileSystemEvent] =
    // First check if directory exists
    Stream.eval(validateDirectory(directory)).flatMap { isValid =>
      if isValid then
        // Record this monitoring session
        Stream.eval(
          updateMonitoringInfo(directory, recursive, fileFilter)
        ) >> monitorDirectoryImpl(directory, recursive, fileFilter)
      else
        // Don't continue if directory is invalid
        Stream.empty
    }

  private def monitorDirectoryImpl(
                                    directory: Path,
                                    recursive: Boolean,
                                    fileFilter: Path => Boolean
                                  ): Stream[F, FileSystemEvent] =
    // Determine if we can use native file watching or need to fall back to polling
    val watchEvents = Stream.eval(Files[F].isWatchable(directory)).flatMap { isWatchable =>
      if isWatchable then
        // Use native file watching
        logger.debug(s"Using native file watching for $directory") *>
          Files[F].watch(directory)
            .evalMap(handleWatchEvent(directory, _, fileFilter))
            .unNone
      else
        // Fall back to polling
        logger.info(s"Native file watching not available for $directory, falling back to polling") *>
          pollDirectory(directory, defaultPollingInterval, fileFilter)
    }

    // If recursive, also watch subdirectories
    val subdirWatching = if recursive then
      Stream.eval(findSubdirectories(directory)).flatMap { subdirs =>
        subdirs
          .filter(dir => fileFilter(dir)) // Apply filter to directories too
          .map(dir => monitorDirectoryImpl(dir, recursive, fileFilter))
          .foldMonoid  // Combine all subdir streams
      }
    else
      Stream.empty

    // Combine directory watching with subdirectory watching
    watchEvents.merge(subdirWatching)
      // Apply additional processing or filtering
      .evalTap(event => logger.debug(s"Detected filesystem event: ${event.eventType} - ${event.filePath}"))

  /**
   * Set up monitoring on system directories considered high risk
   */
  def monitorHighRiskDirectories: Stream[F, FileSystemEvent] =
    Stream.eval(logger.info(s"Setting up monitoring on ${highRiskDirectories.size} high-risk system directories")) >>
      highRiskDirectories
        .map(dir => monitorDirectory(
          dir,
          recursive = false,  // Don't recurse into system directories by default for performance
          fileFilter = isSuspiciousFile  // Only monitor suspicious files
        ))
        .foldMonoid
        // Save all detected events to the repository
        .evalTap(event => repository.save(event))
        // Respond to suspicious events immediately
        .evalTap(handleSuspiciousFile)

  /**
   * Respond to a suspicious file event
   */
  def handleSuspiciousFile(event: FileSystemEvent): F[ResponseAction] =
    val filePath = Path(event.filePath)

    for
      // Log the suspicious activity
      _ <- logger.warn(s"Responding to suspicious file activity: ${event.eventType} - ${event.filePath}")

      // If it's a file creation or modification, scan it for viruses
      scanResult <- if event.eventType == FileActivityType.Created ||
        event.eventType == FileActivityType.Modified then
        virusScanService.scanFile(filePath)
      else
        none[VirusDetection].pure[F]

      // Determine appropriate response based on scan result
      action <- scanResult match
        case Some(detection) =>
          // Virus detected, quarantine the file
          logger.error(s"Virus detected in ${event.filePath}: ${detection.details}") *>
            quarantineFile(filePath).as(ResponseAction.Quarantined)

        case None if event.severity == Severity.High || event.severity == Severity.Critical =>
          // No virus but high severity, monitor closely
          logger.warn(s"No virus detected but suspicious high-severity activity: ${event.filePath}") *>
            ResponseAction.Monitored.pure[F]

        case _ =>
          // Normal activity or low severity
          ResponseAction.NoAction.pure[F]

      // Update the event with the response action
      updatedEvent = event.copy(responseAction = Some(action))
      _ <- repository.update(updatedEvent)
    yield action

  /**
   * Get information about currently monitored directories
   */
  def getMonitoringStatus: F[List[MonitoringInfo]] =
    activeMonitoring.pure[F]

  // Helper methods

  /**
   * Check if a file is suspicious based on extension, permissions, or patterns
   */
  private def isSuspiciousFile(path: Path): Boolean =
    val fileName = path.fileName.toString.toLowerCase
    val extension = fileName.lastIndexOf('.') match
      case -1 => ""  // No extension
      case i => fileName.substring(i + 1)

    // Check for dangerous extensions
    dangerousExtensions.contains(extension) ||
      // Check for hidden files (Unix-style)
      fileName.startsWith(".") ||
      // Check for suspicious naming patterns
      fileName.contains("temp") && dangerousExtensions.contains(extension) ||
      fileName.contains("tmp") && dangerousExtensions.contains(extension) ||
      // Suspicious Windows-specific patterns
      fileName.endsWith(".dll") && !path.toString.toLowerCase.contains("windows") ||
      // Scripts in unusual locations
      extension == "sh" && path.toString.toLowerCase.contains("tmp")

  /**
   * Move a suspicious file to quarantine
   */
  private def quarantineFile(path: Path): F[Path] =
    // Create quarantine directory if it doesn't exist
    val quarantineBasePath = if hostInfo.os.toLowerCase.contains("windows") then
      Path("C:\\ProgramData\\EndsecSecurity\\Quarantine")
    else
      Path("/var/lib/endsec/quarantine")

    for
      _ <- FileSystemErrorUtils.ensureDirectoryExists(quarantineBasePath)
      fileName = path.fileName.toString
      timestamp = Instant.now().toEpochMilli
      // Use a timestamp to avoid name collisions
      quarantinePath = quarantineBasePath / s"${timestamp}_${fileName}"
      _ <- FileSystemErrorUtils.safeMoveFile(path, quarantinePath)
      _ <- logger.info(s"Quarantined suspicious file from $path to $quarantinePath")
    yield quarantinePath

  /**
   * Handle a watch event and convert it to a FileSystemEvent if suspicious
   */
  private def handleWatchEvent(
                                basePath: Path,
                                event: WatchEvent,
                                fileFilter: Path => Boolean
                              ): F[Option[FileSystemEvent]] =
    val path = basePath.resolve(event.path)

    // Only process events for files that match our filter
    if !fileFilter(path) then
      none[FileSystemEvent].pure[F]
    else
      event.eventType match
        case EventKind.ENTRY_CREATE =>
          createFileSystemEvent(path, FileActivityType.Created, basePath).map(Some(_))

        case EventKind.ENTRY_MODIFY =>
          createFileSystemEvent(path, FileActivityType.Modified, basePath).map(Some(_))

        case EventKind.ENTRY_DELETE =>
          createFileSystemEvent(path, FileActivityType.Deleted, basePath).map(Some(_))

        case _ =>
          none[FileSystemEvent].pure[F]

  /**
   * Create a FileSystemEvent from a detected filesystem change
   */
  private def createFileSystemEvent(
                                     path: Path,
                                     activityType: FileActivityType,
                                     baseDir: Path
                                   ): F[FileSystemEvent] =
    for
      isDirectory <- Files[F].isDirectory(path).attempt.map {
        case Right(isDir) => isDir
        case Left(_) => false  // Path might not exist anymore for DELETE events
      }
      isHidden <- isHiddenFile(path)
      isSuspicious = isSuspiciousFile(path)
      severity = determineSeverity(path, activityType, isHidden, isSuspicious)
      event = FileSystemEvent(
        severity = severity,
        source = "FileMonitor",
        details = s"${activityType} ${if isDirectory then "directory" else "file"}: ${path.fileName}",
        timestamp = Instant.now(),
        filePath = path.toString,
        eventType = activityType,
        baseDirectory = baseDir.toString,
        isHidden = isHidden,
        isDirectory = isDirectory,
        responseAction = None
      )
    yield event

  /**
   * Determine the severity of a filesystem event
   */
  private def determineSeverity(
                                 path: Path,
                                 activityType: FileActivityType,
                                 isHidden: Boolean,
                                 isSuspicious: Boolean
                               ): Severity =
    val fileName = path.fileName.toString.toLowerCase
    val extension = fileName.lastIndexOf('.') match
      case -1 => ""  // No extension
      case i => fileName.substring(i + 1)

    // Higher severity for executable content
    val executableExtensions = Set("exe", "dll", "bat", "cmd", "ps1", "vbs", "sh")
    val isExecutable = executableExtensions.contains(extension)

    // Higher severity for system paths
    val isSystemPath = path.toString.toLowerCase.contains("system32") ||
      path.toString.toLowerCase.contains("/bin/") ||
      path.toString.toLowerCase.contains("/sbin/")

    // Determine severity based on multiple factors
    (activityType, isExecutable, isHidden, isSystemPath, isSuspicious) match
      case (_, true, true, true, _) => Severity.Critical  // Hidden executable in system path
      case (_, true, _, true, _) => Severity.High         // Executable in system path
      case (FileActivityType.Created, true, true, _, _) => Severity.High  // New hidden executable
      case (FileActivityType.Modified, true, _, _, _) => Severity.High    // Modified executable
      case (_, _, _, true, true) => Severity.High         // Suspicious file in system path
      case (FileActivityType.Created, true, _, _, _) => Severity.Medium   // New executable
      case (_, _, true, _, true) => Severity.Medium       // Hidden suspicious file
      case (_, true, _, _, _) => Severity.Medium          // Any executable
      case (_, _, true, _, _) => Severity.Low             // Hidden file
      case (_, _, _, _, true) => Severity.Low             // Suspicious file
      case _ => Severity.Info                             // Everything else

  /**
   * Check if a file is hidden
   */
  private def isHiddenFile(path: Path): F[Boolean] =
    Files[F].isHidden(path).attempt.map {
      case Right(hidden) => hidden
      case Left(_) => false  // If we can't check, assume not hidden
    }

  /**
   * Find all subdirectories of a directory
   */
  private def findSubdirectories(path: Path): F[List[Path]] =
    Files[F].walk(path, 1)  // Depth 1 to just get immediate children
      .filter(p => p != path)
      .evalFilter(Files[F].isDirectory)
      .compile
      .toList

  /**
   * Validate that a directory exists and is actually a directory
   */
  private def validateDirectory(directory: Path): F[Boolean] =
    Files[F].exists(directory).flatMap { exists =>
      if exists then
        Files[F].isDirectory(directory)
      else
        logger.warn(s"Directory to monitor does not exist: $directory") *>
          false.pure[F]
    }

  /**
   * Poll a directory for changes when native file watching is not available
   */
  private def pollDirectory(
                             directory: Path,
                             interval: FiniteDuration,
                             fileFilter: Path => Boolean
                           ): Stream[F, FileSystemEvent] =
    // Use a simple polling approach
    def listDirectoryContent(): F[Map[Path, FileMetadata]] =
      Files[F].list(directory)
        .filter(fileFilter)
        .evalMap(path => getFileMetadata(path).map(meta => (path, meta)))
        .compile
        .toList
        .map(_.toMap)

    // Keep track of previous directory state
    Stream.eval(listDirectoryContent()).flatMap { initialState =>
      // Create a ticker to poll at the specified interval
      fs2.Stream.fixedDelay[F](interval)
        .evalMap(_ =>
          // Get current directory content
          listDirectoryContent().flatMap { currentState =>
            // Look for new or modified files
            val changes = findChanges(initialState, currentState)
            // Update state for next iteration
            changes.traverse {
              case (path, Change.Created) =>
                createFileSystemEvent(path, FileActivityType.Created, directory)
              case (path, Change.Modified) =>
                createFileSystemEvent(path, FileActivityType.Modified, directory)
              case (path, Change.Deleted) =>
                createFileSystemEvent(path, FileActivityType.Deleted, directory)
            }.map(events => (events, currentState))
          }
        )
        .flatMap { case (events, newState) =>
          // Emit found events and update reference state
          Stream.eval(Ref[F].of(newState)).flatMap { stateRef =>
            Stream.emits(events)
          }
        }
    }

  /**
   * Get metadata about a file for polling comparison
   */
  private def getFileMetadata(path: Path): F[FileMetadata] =
    for
      exists <- Files[F].exists(path)
      attrs <- if exists then Files[F].getLastModifiedTime(path).map(Some(_)) else None.pure[F]
      size <- if exists then Files[F].size(path).map(Some(_)) else None.pure[F]
    yield FileMetadata(
      exists = exists,
      lastModified = attrs,
      size = size
    )

  /**
   * Find changes between two directory snapshots
   */
  private def findChanges(
                           oldState: Map[Path, FileMetadata],
                           newState: Map[Path, FileMetadata]
                         ): List[(Path, Change)] =
    val created = newState.keys.filterNot(oldState.contains).map(p => (p, Change.Created)).toList

    val deleted = oldState.keys.filterNot(newState.contains).map(p => (p, Change.Deleted)).toList

    val modified = newState.keys.filter(oldState.contains).filter { path =>
      val oldMeta = oldState(path)
      val newMeta = newState(path)
      oldMeta.lastModified != newMeta.lastModified || oldMeta.size != newMeta.size
    }.map(p => (p, Change.Modified)).toList

    created ++ deleted ++ modified

  /**
   * Update the monitoring info when a new directory is monitored
   */
  private def updateMonitoringInfo(
                                    directory: Path,
                                    recursive: Boolean,
                                    fileFilter: Path => Boolean
                                  ): F[Unit] =
    Async[F].delay {
      val info = MonitoringInfo(
        path = directory.toString,
        recursive = recursive,
        startTime = Instant.now(),
        filterDescription = fileFilter.toString
      )
      activeMonitoring = info :: activeMonitoring.filterNot(_.path == directory.toString)
    }

/** Simple enum for tracking changes in polling */
private enum Change:
  case Created, Modified, Deleted

/** Metadata about a file for tracking changes */
private case class FileMetadata(
                                 exists: Boolean,
                                 lastModified: Option[java.nio.file.attribute.FileTime],
                                 size: Option[Long]
                               )

/** Information about an active directory monitoring session */
case class MonitoringInfo(
                           path: String,
                           recursive: Boolean,
                           startTime: Instant,
                           filterDescription: String
                         )

/** Type of response action taken for a suspicious file */
enum ResponseAction:
  case NoAction, Monitored, Quarantined, Deleted, Alerted