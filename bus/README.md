# Kamune Desktop (Bus)

A desktop application for secure peer-to-peer encrypted messaging using the Kamune protocol.

## Overview

This is a Tauri 2 application that provides a graphical interface for the Kamune secure messaging library. It consists of:

- **Frontend**: Svelete UI in `src/`
- **Rust Backend**: Tauri commands and daemon bridge in `src-tauri/`
- **Go Daemon**: Spawned as a child process for actual Kamune protocol handling
