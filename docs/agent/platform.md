# Platform & language direction

> Moved verbatim from `CLAUDE.md` (the always-loaded core keeps a summary and points here).
> Read before using a JDK API newer than Java 8 in code Android consumes, adding a module, or picking an HTTP client. "The multi-PR section" means `multi-pr-plans.md`.

## Platform & language direction

- **Android compatibility is a first-class concern.** This is ultimately a wallet
  library that has to run inside an Android app (`:android-app`, minSdk 29).
  Every change needs to keep the consumer working: avoid JVM-only APIs that
  the Android runtime / `coreLibraryDesugaring` can't cover, mind APK / DEX
  size, and prefer libraries with known Android support. `java.net.http` is
  not desugared and is not available below API 33 — do not use it.
- **minSdk 29 JDK-API budget (verified empirically against R8's backport list
  and the desugar_jdk_libs 2.1.5 config, 2026-08).** Safe at minSdk 29 via D8
  backports + desugaring: `List/Set/Map.of`/`copyOf`, `Map.entry`,
  `String.strip/isBlank/repeat`, `Collection.toArray(IntFunction)`,
  `Optional.isEmpty`, `Predicate.not`, `Collectors.toUnmodifiable*`, and (from
  desugar_jdk_libs 2.1.5) `Stream.toList()`. NOT covered — use the `:core`
  replacements: `CompletableFuture.failedFuture/orTimeout/exceptionallyCompose`
  → `core.concurrent.Futures`; `java.util.HexFormat` → `core.encoding.Hex`;
  `BigInteger.intValueExact/longValueExact` → `core.math.BigIntegers`;
  `Path.of` → `Paths.get`; `InputStream.readAllBytes/readNBytes/transferTo`
  and `Files.readString/writeString` → a manual drain loop /
  `Files.readAllBytes` + `Files.write`. Hosts (android-app/app/app-desktop)
  don't import the `:core` helpers — they inline the few lines instead (hosts
  talk only to `:myotis-api`). The ENFORCEMENT is
  `scripts/check_apk_min_api.py`, run by the android-apk workflow against the
  built APK's dex — the post-desugaring ground truth — on pushes to `main`, on
  PRs into `main` and on dispatch; a part PR into a feature branch does not
  build the APK (see the multi-PR section), so for a feature plan this check
  first runs at the final PR unless a part dispatches the workflow. It also resolves calls
  that reach a JDK method through a third-party subclass, which lint-style
  source checks and a naive api-versions.xml lookup both miss (that is exactly
  how `SnappyFramedInputStream.readAllBytes()` once slipped through), plus
  class-level references (extends/checkcast of a post-29 `java.*` class). It
  is deliberately fail-closed: pre-36.1 platform databases don't record every
  policed API (`Files.readString` first appears in the android-36.1 database),
  so the script refuses to scan against a database that cannot resolve its
  canary APIs rather than passing vacuously.
- **JVM 17 is the default source/target.** New modules should compile to
  Java 17 class files (`sourceCompatibility = JavaVersion.VERSION_17`,
  `targetCompatibility = JavaVersion.VERSION_17`) so they're consumable from
  the Android module. The toolchain may run on Java 21, and existing modules
  ship 21 class files only for transitive reasons (`:networking` because of
  ConsenSys discv5 26.4.0; `:myotis-evm` because of Besu's `evm` module both
  publishing Gradle module metadata declaring a JVM-21 floor). Only diverge
  when a transitive forces it, and document the reason in the module's
  build file.
- **Long-term direction is Kotlin + Compose Multiplatform.** New code can
  still land in Java where it lowers risk, but expect a migration to Kotlin
  to enable Compose Multiplatform consumers (Android + desktop + iOS). Public
  APIs should not depend on Java-only types that block Kotlin/Native or JS
  targets later. Avoid leaking `CompletableFuture` into shared APIs designed
  for multiplatform; expose suspending or library-neutral shapes instead.
- **HTTP client: Ktor.** When a feature needs HTTP (e.g. CCIP-Read gateways
  in `myotis-evm`), use Ktor — not OkHttp, not `java.net.http`. Ktor has
  Multiplatform-ready engines and runs on Android.
