@echo off
echo Compilando para Windows...
set GOOS=windows
set GOARCH=amd64
go build -o build/assinatura-windows.exe ./cmd/assinatura

echo Compilando para Linux...
set GOOS=linux
set GOARCH=amd64
go build -o build/assinatura-linux ./cmd/assinatura

echo Compilando para MacOS...
set GOOS=darwin
set GOARCH=amd64
go build -o build/assinatura-macos ./cmd/assinatura

echo Build sucess in folder /build