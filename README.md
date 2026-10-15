# Myotis engine library — Maven repository

The `eth.myotis` artifacts of every release (docs/android-library.md on `main`),
laid out as a Maven repository and served by raw.githubusercontent.com, so a
build needs no GitHub token:

```kotlin
maven {
    url = uri("https://raw.githubusercontent.com/biafra23/myotis/maven-repo")
    content { includeGroup("eth.myotis") }
}
```

Written by the engine-library workflow on each `v*` tag; never edited by hand.
