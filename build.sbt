// build.sbt
ThisBuild / version := "0.1.0"
ThisBuild / scalaVersion := "3.3.1"
ThisBuild / organization := "com.endsec"

lazy val root = (project in file("."))
  .settings(
    name := "ns5",
    libraryDependencies ++= Seq(
      "org.typelevel" %% "cats-core" % "2.9.0",
      "org.typelevel" %% "cats-effect" % "3.5.1",
      "co.fs2" %% "fs2-core" % "3.7.0",
      "co.fs2" %% "fs2-io" % "3.7.0",
      "org.http4s" %% "http4s-ember-client" % "0.23.23",
      "org.http4s" %% "http4s-ember-server" % "0.23.23",
      "org.http4s" %% "http4s-dsl" % "0.23.23",
      "org.http4s" %% "http4s-circe" % "0.23.23",
      "io.circe" %% "circe-generic" % "0.14.5",
      "io.circe" %% "circe-parser" % "0.14.5",
      "org.typelevel" %% "log4cats-slf4j" % "2.5.0",
      "ch.qos.logback" % "logback-classic" % "1.4.11",
      "com.monovore" %% "decline" % "2.4.1",
      "com.monovore" %% "decline-effect" % "2.4.1",
      "org.scalameta" %% "munit" % "0.7.29" % Test,
      "org.typelevel" %% "munit-cats-effect-3" % "1.0.7" % Test,
      "com.github.pathikrit" %% "better-files" % "3.9.2",
      "io.github.resilience4j" % "resilience4j-all" % "2.0.2"
    ),
    scalacOptions ++= Seq(
      "-Xcheck-macros",
      "-source:3.3",
      "-unchecked",
      "-deprecation",
      "-feature",
      "-explain"
    )
  )