package com.endsec.repositories

import cats.effect.*
import cats.syntax.all.*
import cats.effect.std.UUIDGen

import com.endsec.domain.*

import scala.collection.concurrent.TrieMap
import java.time.Instant
import java.util.UUID
import scala.reflect.ClassTag

/** Repository interface for storing and retrieving security events */
trait SecurityEventRepository[F[_]]:
  def save[A <: SecurityEvent](event: A): F[Unit]
  def getById[A <: SecurityEvent: ClassTag](id: UUID): F[Option[A]]
  def getRecent[A <: SecurityEvent: ClassTag](limit: Int): F[List[A]]
  def getBySeverity[A <: SecurityEvent: ClassTag](severity: Severity): F[List[A]]
  def getByTimeRange[A <: SecurityEvent: ClassTag](start: Instant, end: Instant): F[List[A]]
  def count[A <: SecurityEvent: ClassTag]: F[Int]
  def deleteById[A <: SecurityEvent](id: UUID): F[Boolean]
  def clear: F[Unit]

object SecurityEventRepository:
  /** Creates an in-memory implementation of the repository */
  def inMemory[F[_]: Sync]: F[SecurityEventRepository[F]] =
    Sync[F].pure(new InMemorySecurityEventRepository[F])

/** In-memory implementation of SecurityEventRepository */
private class InMemorySecurityEventRepository[F[_]: Sync] extends SecurityEventRepository[F]:
  // Using a concurrent map to store the events
  private val storage = TrieMap.empty[UUID, SecurityEvent]

  override def save[A <: SecurityEvent](event: A): F[Unit] =
    Sync[F].delay(storage.put(event.id, event)).void

  override def getById[A <: SecurityEvent: ClassTag](id: UUID): F[Option[A]] =
    Sync[F].delay {
      storage.get(id).collect {
        case event if implicitly[ClassTag[A]].runtimeClass.isInstance(event) =>
          event.asInstanceOf[A]
      }
    }

  override def getRecent[A <: SecurityEvent: ClassTag](limit: Int): F[List[A]] =
    Sync[F].delay {
      storage.values
        .collect {
          case event if implicitly[ClassTag[A]].runtimeClass.isInstance(event) =>
            event.asInstanceOf[A]
        }
        .toList
        .sortBy(_.timestamp)
        .reverse
        .take(limit)
    }

  override def getBySeverity[A <: SecurityEvent: ClassTag](severity: Severity): F[List[A]] =
    Sync[F].delay {
      storage.values
        .collect {
          case event if implicitly[ClassTag[A]].runtimeClass.isInstance(event) && event.severity == severity =>
            event.asInstanceOf[A]
        }
        .toList
        .sortBy(_.timestamp)
        .reverse
    }

  override def getByTimeRange[A <: SecurityEvent: ClassTag](start: Instant, end: Instant): F[List[A]] =
    Sync[F].delay {
      storage.values
        .collect {
          case event if implicitly[ClassTag[A]].runtimeClass.isInstance(event) &&
            event.timestamp.isAfter(start) &&
            event.timestamp.isBefore(end) =>
            event.asInstanceOf[A]
        }
        .toList
        .sortBy(_.timestamp)
    }

  override def count[A <: SecurityEvent: ClassTag]: F[Int] =
    Sync[F].delay {
      storage.values.count(event => implicitly[ClassTag[A]].runtimeClass.isInstance(event))
    }

  override def deleteById[A <: SecurityEvent](id: UUID): F[Boolean] =
    Sync[F].delay {
      storage.remove(id).isDefined
    }

  override def clear: F[Unit] =
    Sync[F].delay {
      storage.clear()
    }

/** Database-backed implementation of SecurityEventRepository 
 *
 * In a real application, this would interact with a database like PostgreSQL, 
 * MongoDB, etc. For this example, we're only implementing the in-memory version.
 */
// class DatabaseSecurityEventRepository[F[_]: Async](dbPool: Resource[F, Connection]) extends SecurityEventRepository[F] {
//   // Implementation would go here, using SQL or an ORM
// }