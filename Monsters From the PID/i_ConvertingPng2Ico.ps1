$imgPath = "C:\Users\CAMELLA\source\repos\N_OneTool\onetool-1\Images"
$icoPath = "C:\Users\CAMELLA\OneDrive - Federal Bureau of Investigation\Documents\Desktop"
$in = "OneToolIcon-Black.png"
$out = "OneToolIcon-Black.ico"
$in = "OneToolIcon-Gold.png"
$out = "OneToolIcon-Gold.ico"


#region - 
    Add-Type -AssemblyName System.Drawing

    function ConvertTo-Icon_1 {
       param(
           [Parameter(Mandatory=$true)]
           $bitmapPath,
           $iconPath = "$env:temp\newicon.ico"
       )
       if (Test-Path $bitmapPath) {
           $b = [System.Drawing.Bitmap]::FromFile($bitmapPath)
           $icon = [System.Drawing.Icon]::FromHandle($b.GetHicon())
           $file = New-Object System.IO.FileStream($iconPath, 'OpenOrCreate')
           $icon.Save($file)
           $file.Close()
           $icon.Dispose()
           explorer "/SELECT,$iconpath"
       } else {
           Write-Warning "$BitmapPath does not exist"
       }
    }
    ConvertTo-Icon_1 -bitmapPath "$imgPath\$in" -iconPath "$icoPath\$out"
 
#endregion
#region - 
    function ConvertTo-Icon
    {
        <#
        .Synopsis
            Converts image to icons
        .Description
            Converts an image to an icon
        .Example
            ConvertTo-Icon -File .\Logo.png -OutputFile .\Favicon.ico
        #>
        [CmdletBinding()]
        param(
        # The file
        [Parameter(Mandatory=$true, Position=0,ValueFromPipelineByPropertyName=$true)]
        [Alias('Fullname')]
        [string]$File,
    
        # If set, will output bytes instead of creating a file
        [switch]$InMemory,
    
        # If provided, will output the icon to a location
        [Parameter(Position=1, ValueFromPipelineByPropertyName=$true)]
        [string]$OutputFile
        )
    
        begin {
            Add-Type -AssemblyName System.Windows.Forms, System.Drawing
        
        }
    
        process {
            #region Load Icon
            $resolvedFile = $ExecutionContext.SessionState.Path.GetResolvedPSPathFromPSPath($file)
            if (-not $resolvedFile) { return }
            $loadedImage = [Drawing.Image]::FromFile($resolvedFile)
            $intPtr = New-Object IntPtr
            $thumbnail = $loadedImage.GetThumbnailImage(72, 72, $null, $intPtr)
            $bitmap = New-Object Drawing.Bitmap $thumbnail 
            $bitmap.SetResolution(72, 72); 
            $icon = [System.Drawing.Icon]::FromHandle($bitmap.GetHicon());         
            #endregion Load Icon

            #region Save Icon
            if ($InMemory) {                        
                $memStream = New-Object IO.MemoryStream
                $icon.Save($memStream) 
                $memStream.Seek(0,0)
                $bytes = New-Object Byte[] $memStream.Length
                $memStream.Read($bytes, 0, $memStream.Length)                        
                $bytes
            } elseif ($OutputFile) {
                $resolvedOutputFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($outputFile)
                $fileStream = [IO.File]::Create("$resolvedOutputFile")                               
                $icon.Save($fileStream) 
                $fileStream.Close()               
            }
            #endregion Save Icon

            #region Cleanup
            $icon.Dispose()
            $bitmap.Dispose()
            #endregion Cleanup

        }
    }

    ConvertTo-Icon -File "$imgPath\$in" -OutputFile "$icoPath\$out"
#endregion
#region - 
    $TypeDefinition = @'
    using System.Drawing;
    using System.Drawing.Imaging;
    using System.IO;
    using System.Collections.Generic;
    using System.Drawing.Drawing2D;

    /// <summary>
    /// Adapted from this gist: https://gist.github.com/darkfall/1656050
    /// Provides helper methods for imaging
    /// </summary>
    public static class ImagingHelper
    {
        /// <summary>
        /// Converts a PNG image to a icon (ico) with all the sizes windows likes
        /// </summary>
        /// <param name="inputBitmap">The input bitmap</param>
        /// <param name="output">The output stream</param>
        /// <returns>Wether or not the icon was succesfully generated</returns>
        public static bool ConvertToIcon(Bitmap inputBitmap, Stream output)
        {
            if (inputBitmap == null)
                return false;

            int[] sizes = new int[] { 256, 48, 32, 16 };

            // Generate bitmaps for all the sizes and toss them in streams
            List<MemoryStream> imageStreams = new List<MemoryStream>();
            foreach (int size in sizes)
            {
                Bitmap newBitmap = ResizeImage(inputBitmap, size, size);
                if (newBitmap == null)
                    return false;
                MemoryStream memoryStream = new MemoryStream();
                newBitmap.Save(memoryStream, ImageFormat.Png);
                imageStreams.Add(memoryStream);
            }

            BinaryWriter iconWriter = new BinaryWriter(output);
            if (output == null || iconWriter == null)
                return false;

            int offset = 0;

            // 0-1 reserved, 0
            iconWriter.Write((byte)0);
            iconWriter.Write((byte)0);

            // 2-3 image type, 1 = icon, 2 = cursor
            iconWriter.Write((short)1);

            // 4-5 number of images
            iconWriter.Write((short)sizes.Length);

            offset += 6 + (16 * sizes.Length);

            for (int i = 0; i < sizes.Length; i++)
            {
                // image entry 1
                // 0 image width
                iconWriter.Write((byte)sizes[i]);
                // 1 image height
                iconWriter.Write((byte)sizes[i]);

                // 2 number of colors
                iconWriter.Write((byte)0);

                // 3 reserved
                iconWriter.Write((byte)0);

                // 4-5 color planes
                iconWriter.Write((short)0);

                // 6-7 bits per pixel
                iconWriter.Write((short)32);

                // 8-11 size of image data
                iconWriter.Write((int)imageStreams[i].Length);

                // 12-15 offset of image data
                iconWriter.Write((int)offset);

                offset += (int)imageStreams[i].Length;
            }

            for (int i = 0; i < sizes.Length; i++)
            {
                // write image data
                // png data must contain the whole png data file
                iconWriter.Write(imageStreams[i].ToArray());
                imageStreams[i].Close();
            }

            iconWriter.Flush();

            return true;
        }

        /// <summary>
        /// Converts a PNG image to a icon (ico)
        /// </summary>
        /// <param name="input">The input stream</param>
        /// <param name="output">The output stream</param
        /// <returns>Wether or not the icon was succesfully generated</returns>
        public static bool ConvertToIcon(Stream input, Stream output)
        {
            Bitmap inputBitmap = (Bitmap)Bitmap.FromStream(input);
            return ConvertToIcon(inputBitmap, output);
        }

        /// <summary>
        /// Converts a PNG image to a icon (ico)
        /// </summary>
        /// <param name="inputPath">The input path</param>
        /// <param name="outputPath">The output path</param>
        /// <returns>Wether or not the icon was succesfully generated</returns>
        public static bool ConvertToIcon(string inputPath, string outputPath)
        {
            using (FileStream inputStream = new FileStream(inputPath, FileMode.Open))
            using (FileStream outputStream = new FileStream(outputPath, FileMode.OpenOrCreate))
            {
                return ConvertToIcon(inputStream, outputStream);
            }
        }



        /// <summary>
        /// Converts an image to a icon (ico)
        /// </summary>
        /// <param name="inputImage">The input image</param>
        /// <param name="outputPath">The output path</param>
        /// <returns>Wether or not the icon was succesfully generated</returns>
        public static bool ConvertToIcon(Image inputImage, string outputPath)
        {
            using (FileStream outputStream = new FileStream(outputPath, FileMode.OpenOrCreate))
            {
                return ConvertToIcon(new Bitmap(inputImage), outputStream);
            }
        }


        /// <summary>
        /// Resize the image to the specified width and height.
        /// Found on stackoverflow: https://stackoverflow.com/questions/1922040/resize-an-image-c-sharp
        /// </summary>
        /// <param name="image">The image to resize.</param>
        /// <param name="width">The width to resize to.</param>
        /// <param name="height">The height to resize to.</param>
        /// <returns>The resized image.</returns>
        public static Bitmap ResizeImage(Image image, int width, int height)
        {
            var destRect = new Rectangle(0, 0, width, height);
            var destImage = new Bitmap(width, height);

            destImage.SetResolution(image.HorizontalResolution, image.VerticalResolution);

            using (var graphics = Graphics.FromImage(destImage))
            {
                graphics.CompositingMode = CompositingMode.SourceCopy;
                graphics.CompositingQuality = CompositingQuality.HighQuality;
                graphics.InterpolationMode = InterpolationMode.HighQualityBicubic;
                graphics.SmoothingMode = SmoothingMode.HighQuality;
                graphics.PixelOffsetMode = PixelOffsetMode.HighQuality;

                using (var wrapMode = new ImageAttributes())
                {
                    wrapMode.SetWrapMode(WrapMode.TileFlipXY);
                    graphics.DrawImage(image, destRect, 0, 0, image.Width, image.Height, GraphicsUnit.Pixel, wrapMode);
                }
            }

            return destImage;
        }
    }
'@

    Add-Type -TypeDefinition $TypeDefinition -ReferencedAssemblies 'System.Drawing','System.IO','System.Collections'

    <#
    .Synopsis
        Converts .PNG images to icons
    .Description
        Converts a .PNG image to an icon
    .Example
        ConvertTo-Icon -Path .\Logo.png -Destination .\Favicon.ico
    #>
    Function ConvertTo-Icon
    {
        [CmdletBinding()]
        param(
        # The file
        [Parameter(Mandatory=$true, Position=0,ValueFromPipelineByPropertyName=$true)]
        [Alias('Fullname','File')]
        [string]$Path,
   
        # If provided, will output the icon to a location
        [Parameter(Position=1, ValueFromPipelineByPropertyName=$true)]
        [Alias('OutputFile')]
        [string]$Destination
        )
    
        Begin
        {
            If (-Not 'ImagingHelper' -as [Type])
            {
                Throw 'The custom "ImagingHelper" type is not loaded'
            }
        }
    
        Process
        {
            #region Resolve Path
            $ResolvedFile = $ExecutionContext.SessionState.Path.GetResolvedPSPathFromPSPath($Path)
            If (-not $ResolvedFile)
            {
                return
            }
            #endregion        

            [ImagingHelper]::ConvertToIcon($ResolvedFile[0].Path,$Destination)
        }
        End
        {
        }
    }
    ConvertTo-Icon -File "$imgPath\$in" -OutputFile "$icoPath\$out"

#endregion
#region - 
    Add-Type -AssemblyName System.Drawing


    function Convert-ToIcon {
        param (
            [System.Drawing.Bitmap]$InputBitmap,
            [System.IO.Stream]$OutputStream
        )
        function Resize-Image {
            param (
                [System.Drawing.Image]$Image,
                [int]$Width,
                [int]$Height
            )

            $destRect = New-Object System.Drawing.Rectangle(0, 0, $Width, $Height)
            $destImage = New-Object System.Drawing.Bitmap($Width, $Height)
            $destImage.SetResolution($Image.HorizontalResolution, $Image.VerticalResolution)

            $graphics = [System.Drawing.Graphics]::FromImage($destImage)
            $graphics.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
            $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
            $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
            $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality

            $wrapMode = New-Object System.Drawing.Imaging.ImageAttributes
            $wrapMode.SetWrapMode([System.Drawing.Drawing2D.WrapMode]::TileFlipXY)

            $graphics.DrawImage($Image, $destRect, 0, 0, $Image.Width, $Image.Height, [System.Drawing.GraphicsUnit]::Pixel, $wrapMode)

            $graphics.Dispose()
            $wrapMode.Dispose()

            return $destImage
        }

        if (-not $InputBitmap) { return $false }

        $sizes = @(256, 48, 32, 16)
        $imageStreams = @()

        foreach ($size in $sizes) {
            $newBitmap = Resize-Image -Image $InputBitmap -Width $size -Height $size
            if (-not $newBitmap) { return $false }

            $memoryStream = New-Object System.IO.MemoryStream
            $newBitmap.Save($memoryStream, [System.Drawing.Imaging.ImageFormat]::Png)
            $imageStreams += $memoryStream
        }

        $writer = New-Object System.IO.BinaryWriter($OutputStream)
        if (-not $writer) { return $false }

        $offset = 6 + (16 * $sizes.Count)

        # ICON header
        $writer.Write([byte]0)
        $writer.Write([byte]0)
        $writer.Write([int16]1)
        $writer.Write([int16]$sizes.Count)

        # Directory entries
        for ($i = 0; $i -lt $sizes.Count; $i++) {
            $sizeToWrite = $sizes[$i]
            if ($sizeToWrite -gt 255) { $sizeToWrite = 0 }

            $writer.Write([byte]$sizeToWrite) # width
            $writer.Write([byte]$sizeToWrite) # height
            $writer.Write([byte]0)            # colors
            $writer.Write([byte]0)            # reserved
            $writer.Write([int16]0)           # color planes
            $writer.Write([int16]32)          # bits per pixel
            $writer.Write([int32]$imageStreams[$i].Length) # size of image data
            $writer.Write([int32]$offset)     # offset

            $offset += $imageStreams[$i].Length
        }

        # Image data
        foreach ($stream in $imageStreams) {
            $writer.Write($stream.ToArray())
            $stream.Close()
        }

        $writer.Flush()
        return $true
    }

    function Convert-FileToIcon {
        param (
            [string]$InputPath,
            [string]$OutputPath
        )

        $inputStream = [System.IO.File]::OpenRead($InputPath)
        $outputStream = [System.IO.File]::Open($OutputPath, [System.IO.FileMode]::Create)
        $bitmap = [System.Drawing.Bitmap]::FromStream($inputStream)

        $result = Convert-ToIcon -InputBitmap $bitmap -OutputStream $outputStream

        $inputStream.Close()
        $outputStream.Close()
        return $result
    }

    Convert-FileToIcon -InputPath "$imgPath\$in" -OutputPath "$icoPath\$out"
#endregion
#region - 
    "$([Environment]::GetFolderPath('Desktop'))\OneToolIcon-Gold.ico"
    Add-Type -AssemblyName System.Drawing

    function Resize-Image {
        param (
            [System.Drawing.Image]$Image,
            [int]$Width,
            [int]$Height
        )

        $destRect = New-Object System.Drawing.Rectangle(0, 0, $Width, $Height)
        $destImage = New-Object System.Drawing.Bitmap($Width, $Height)
        $destImage.SetResolution($Image.HorizontalResolution, $Image.VerticalResolution)

        $graphics = [System.Drawing.Graphics]::FromImage($destImage)
        $graphics.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
        $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
        $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality

        $wrapMode = New-Object System.Drawing.Imaging.ImageAttributes
        $wrapMode.SetWrapMode([System.Drawing.Drawing2D.WrapMode]::TileFlipXY)

        $graphics.DrawImage($Image, $destRect, 0, 0, $Image.Width, $Image.Height, [System.Drawing.GraphicsUnit]::Pixel, $wrapMode)

        $graphics.Dispose()
        $wrapMode.Dispose()

        return $destImage
    }

    function Convert-ToIcon {
        param (
            [System.Drawing.Bitmap]$InputBitmap,
            [System.IO.Stream]$OutputStream
        )

        if (-not $InputBitmap) { return $false }

        $sizes = @(256, 48, 32, 16)
        $imageStreams = @()

        foreach ($size in $sizes) {
            $newBitmap = Resize-Image -Image $InputBitmap -Width $size -Height $size
            if (-not $newBitmap) { return $false }

            $memoryStream = New-Object System.IO.MemoryStream
            $newBitmap.Save($memoryStream, [System.Drawing.Imaging.ImageFormat]::Png)
            $imageStreams += $memoryStream
        }

        $writer = New-Object System.IO.BinaryWriter($OutputStream)
        if (-not $writer) { return $false }

        $offset = 6 + (16 * $sizes.Count)

        # ICON header
        $writer.Write([byte]0)
        $writer.Write([byte]0)
        $writer.Write([int16]1)
        $writer.Write([int16]$sizes.Count)

        # Directory entries
        for ($i = 0; $i -lt $sizes.Count; $i++) {
            $sizeToWrite = $sizes[$i]
            if ($sizeToWrite -gt 255) { $sizeToWrite = 0 }

            $writer.Write([byte]$sizeToWrite) # width
            $writer.Write([byte]$sizeToWrite) # height
            $writer.Write([byte]0)            # colors
            $writer.Write([byte]0)            # reserved
            $writer.Write([int16]0)           # color planes
            $writer.Write([int16]32)          # bits per pixel
            $writer.Write([int32]$imageStreams[$i].Length) # size of image data
            $writer.Write([int32]$offset)     # offset

            $offset += $imageStreams[$i].Length
        }

        # Image data
        foreach ($stream in $imageStreams) {
            $writer.Write($stream.ToArray())
            $stream.Close()
        }

        $writer.Flush()
        return $true
    }

    function Convert-StreamToIcon {
        param (
            [System.IO.Stream]$InputStream,
            [System.IO.Stream]$OutputStream
        )

        $bitmap = [System.Drawing.Bitmap]::FromStream($InputStream)
        return Convert-ToIcon -InputBitmap $bitmap -OutputStream $OutputStream
    }

    function Convert-ImageToIcon {
        param (
            [System.Drawing.Image]$InputImage,
            [string]$OutputPath
        )

        $outputStream = [System.IO.File]::Open($OutputPath, [System.IO.FileMode]::Create)
        $bitmap = New-Object System.Drawing.Bitmap($InputImage)
        $result = Convert-ToIcon -InputBitmap $bitmap -OutputStream $outputStream
        $outputStream.Close()
        return $result
    }

    function Convert-FileToIcon {
        param (
            [string]$InputPath,
            [string]$OutputPath
        )

        $inputStream = [System.IO.File]::OpenRead($InputPath)
        $outputStream = [System.IO.File]::Open($OutputPath, [System.IO.FileMode]::Create)
        $bitmap = [System.Drawing.Bitmap]::FromStream($inputStream)

        $result = Convert-ToIcon -InputBitmap $bitmap -OutputStream $outputStream

        $inputStream.Close()
        $outputStream.Close()
        return $result
    }

    Convert-FileToIcon -InputPath "$imgPath\$in" -OutputPath "$icoPath\$out"
#endregion
