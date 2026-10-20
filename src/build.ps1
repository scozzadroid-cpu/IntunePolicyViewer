# Builds PolicyViewer.exe (WPF) with the .NET Framework 4.x C# compiler included in Windows.
# The UI (MainWindow.xaml) and the icon are embedded as resources: the exe is a single file.
param(
    [string]$Output = (Join-Path $PSScriptRoot '..\PolicyViewer.exe')
)
$ErrorActionPreference = 'Stop'
$fw = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$csc = Join-Path $fw 'csc.exe'
$icon = Join-Path $PSScriptRoot 'app.ico'

if (-not (Test-Path $icon)) {
    Add-Type -AssemblyName System.Drawing
    $bmp = New-Object Drawing.Bitmap 64, 64
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $path = New-Object Drawing.Drawing2D.GraphicsPath
    $r = 18; $path.AddArc(2, 2, $r, $r, 180, 90); $path.AddArc(44, 2, $r, $r, 270, 90); $path.AddArc(44, 44, $r, $r, 0, 90); $path.AddArc(2, 44, $r, $r, 90, 90); $path.CloseFigure()
    $grad = New-Object Drawing.Drawing2D.LinearGradientBrush (New-Object Drawing.Point 0, 0), (New-Object Drawing.Point 64, 64), ([Drawing.Color]::FromArgb(59, 130, 246)), ([Drawing.Color]::FromArgb(99, 102, 241))
    $g.FillPath($grad, $path)
    # Shield
    $shield = New-Object Drawing.Drawing2D.GraphicsPath
    $shield.AddLines([Drawing.PointF[]]@((New-Object Drawing.PointF 32, 12), (New-Object Drawing.PointF 48, 18), (New-Object Drawing.PointF 48, 31)))
    $shield.AddBezier(48, 31, 48, 42, 41, 49, 32, 53)
    $shield.AddBezier(32, 53, 23, 49, 16, 42, 16, 31)
    $shield.AddLines([Drawing.PointF[]]@((New-Object Drawing.PointF 16, 31), (New-Object Drawing.PointF 16, 18)))
    $shield.CloseFigure()
    $g.FillPath((New-Object Drawing.SolidBrush ([Drawing.Color]::White)), $shield)
    # Check mark
    $pen = New-Object Drawing.Pen ([Drawing.Color]::FromArgb(59, 110, 240)), 4.5
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
    $g.DrawLines($pen, [Drawing.Point[]]@((New-Object Drawing.Point 24, 32), (New-Object Drawing.Point 30, 38), (New-Object Drawing.Point 40, 26)))
    $g.Dispose()
    $ms = New-Object IO.MemoryStream
    $bmp.Save($ms, [Drawing.Imaging.ImageFormat]::Png)
    $png = $ms.ToArray()
    $fs = [IO.File]::Create($icon); $bw = New-Object IO.BinaryWriter $fs
    $bw.Write([UInt16]0); $bw.Write([UInt16]1); $bw.Write([UInt16]1)
    $bw.Write([Byte]64); $bw.Write([Byte]64); $bw.Write([Byte]0); $bw.Write([Byte]0)
    $bw.Write([UInt16]1); $bw.Write([UInt16]32); $bw.Write([UInt32]$png.Length); $bw.Write([UInt32]22)
    $bw.Write($png); $bw.Close()
}

$cscArgs = @(
    '/nologo', '/target:winexe', '/optimize+', '/platform:anycpu', '/codepage:65001',
    "/out:$Output", "/win32icon:$icon", "/win32manifest:$(Join-Path $PSScriptRoot 'app.manifest')",
    "/lib:$fw", "/lib:$(Join-Path $fw 'WPF')",
    '/r:System.dll', '/r:System.Core.dll', '/r:System.Xml.dll', '/r:System.Xaml.dll', '/r:System.Management.dll', '/r:Microsoft.CSharp.dll',
    '/r:WindowsBase.dll', '/r:PresentationCore.dll', '/r:PresentationFramework.dll',
    "/resource:$(Join-Path $PSScriptRoot 'MainWindow.xaml'),MainWindow.xaml",
    "/resource:$icon,app.ico",
    (Join-Path $PSScriptRoot 'Program.cs')
)

& $csc @cscArgs
if ($LASTEXITCODE -ne 0) { throw "Build failed ($LASTEXITCODE)" }
Get-Item $Output | Select-Object FullName, Length, LastWriteTime
