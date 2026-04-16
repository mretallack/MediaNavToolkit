#!/bin/bash
# Wine32 container entrypoint
# Handles: user creation, prefix init, wineboot, persistent wineserver
set -e

WINEPREFIX=/home/wineuser/.wine32
WINEARCH=win32
WINEDEBUG=-all
HOST_UID=${HOST_UID:-1000}
HOST_GID=${HOST_GID:-100}

export WINEPREFIX WINEARCH WINEDEBUG

# --- Create user matching host UID/GID ---
if ! id wineuser &>/dev/null; then
    groupadd -g "$HOST_GID" hostgroup 2>/dev/null || true
    useradd -u "$HOST_UID" -g "$HOST_GID" -d /home/wineuser -s /bin/bash -M wineuser 2>/dev/null || true
    mkdir -p /home/wineuser
    chown "$HOST_UID:$HOST_GID" /home/wineuser
fi

# --- Initialize wine prefix if needed ---
SYS32="$WINEPREFIX/drive_c/windows/system32"
DLL_COUNT=$(ls "$SYS32/" 2>/dev/null | wc -l)

if [ "$DLL_COUNT" -lt 100 ]; then
    echo "Initializing wine32 prefix (first run, takes ~5-10 min under QEMU)..."
    mkdir -p "$WINEPREFIX"
    chown "$HOST_UID:$HOST_GID" "$WINEPREFIX"
    timeout 600 su -s /bin/bash wineuser -c \
        "WINEPREFIX=$WINEPREFIX WINEARCH=$WINEARCH WINEDEBUG=-all wineboot -i" 2>/dev/null || true
    su -s /bin/bash wineuser -c "WINEPREFIX=$WINEPREFIX wineserver -k" 2>/dev/null || true
    DLL_COUNT=$(ls "$SYS32/" 2>/dev/null | wc -l)
    echo "Wine prefix created ($DLL_COUNT DLLs)."
fi

# --- Run wineboot if wine version changed ---
# Our marker (.wine-version) tracks whether wineboot has completed for this wine build.
# Wine's own .update-timestamp tracks the wine binary mtime — we don't touch it.
WINE_VERSION=$(wine --version 2>/dev/null || echo "unknown")
MARKER="$WINEPREFIX/.wine-version"
SAVED_VERSION=$(cat "$MARKER" 2>/dev/null || echo "")

if [ "$SAVED_VERSION" != "$WINE_VERSION" ]; then
    echo "Wine version changed ($SAVED_VERSION -> $WINE_VERSION), running wineboot..."
    timeout 600 su -s /bin/bash wineuser -c \
        "WINEPREFIX=$WINEPREFIX WINEARCH=$WINEARCH WINEDEBUG=-all wineboot -u" 2>/dev/null || true
    su -s /bin/bash wineuser -c "WINEPREFIX=$WINEPREFIX wineserver -k" 2>/dev/null || true
    echo "$WINE_VERSION" > "$MARKER"
    chown "$HOST_UID:$HOST_GID" "$MARKER" 2>/dev/null || true
    echo "Wineboot complete."
else
    echo "Wine prefix up to date ($WINE_VERSION, $DLL_COUNT DLLs)."
fi

# --- Start persistent wineserver ---
echo -n "Starting wineserver... "
su -s /bin/bash wineuser -c \
    "WINEPREFIX=$WINEPREFIX WINEARCH=$WINEARCH WINEDEBUG=-all wineserver -p" &
sleep 1
echo "done. Ready."

# --- Drop to user ---
exec su -s /bin/bash wineuser -c \
    "export WINEPREFIX=$WINEPREFIX WINEARCH=$WINEARCH WINEDEBUG=-all HOME=/home/wineuser; exec $*"
