# SelfishNet Companion (Android)

Application Android compagnon (Kotlin + Jetpack Compose + Material 3) permettant de piloter à distance un serveur SelfishNet (Linux, Windows ou Raspberry Pi) sur votre réseau local, **sans root**.

## Ouvrir & Compiler

1. Ouvrez le dossier `android/` dans **Android Studio** (Ladybug / Hedgehog+ avec JDK 17).
2. Laissez Gradle synchroniser les dépendances Jetpack Compose.
3. Cliquez sur **Run** (ou lancez `./gradlew assembleDebug`) pour installer l'APK sur votre téléphone.

## Appairage avec votre PC

Sur Linux :
```bash
sudo selfishnet daemon --api-bind 0.0.0.0 --api-port 8443
```

Sur Windows :
- Cliquez sur le bouton **Appairage Android** dans la fenêtre SelfishNet Windows.

Copiez l'URI `selfishnet://pair?host=...&port=8443&token=...` affichée par le serveur et collez-la dans l'écran d'appairage de l'application Android (ou ouvrez-la directement par lien/QR code).
