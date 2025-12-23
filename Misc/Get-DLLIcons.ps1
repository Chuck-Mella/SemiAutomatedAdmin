Function Dec64 { Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b };
$Shell32_dll_icon_idx = (Dec64 'MSxkZWZhdWx0IGZpbGUgaWNvbg0KMixkZWZhdWx0IGRvY3VtZW50DQozLGRlZmF1bHQgZXhlIGZpbGUNCjQsY2xvc2VkIGZvbGRlcg0KNSxvcGVuZWQgZm9sZGVyDQo2LDUgMS80IGRpc2sNCjcsMyAxLzIgZGlzaw0KOCxvdGhlciByZW1vdmVhYmxlIG1lZGlhDQo5LGhhcmQgZHJpdmUNCjEwLG5ldHdvcmsgZHJpdmUNCjExLGRpc2Nvbm5lY3RlZCBuZXR3b3JrIGRyaXZlDQoxMixjZC1yb20gZHJpdmUNCjEzLHJhbSBkcml2ZQ0KMTQsbmV0d29yayAoZ2xvYmUpDQoxNSxuZXR3b3JrIChtb3VzZSkNCjE2LG15IGNvbXB1dGVyDQoxNyxwcmludGVyDQoxOCxuZXR3b3JrIGNvbXB1dGVyDQoxOSxlbnRpcmUgbmV0d29yaw0KMjAscHJvZ3JhbSBncm91cA0KMjEsbXkgcmVjZW50IGRvY3VtZW50cw0KMjIsY29udHJvbCBwYW5lbA0KMjMsZmluZA0KMjQsaGVscA0KMjUscnVuDQoyNixnb29kIG5pZ2h0IChvbGQgbG9nIG9mZj8pDQoyNyx1bmRvY2sNCjI4LHNodXRkb3duDQoyOSxzaGFyZWQNCjMwLHNob3J0Y3V0DQozMSxzY2hlZHVsZWQgdGFzayBvdmVybGF5DQozMixyZWN5Y2xlIGJpbiBlbXB0eQ0KMzMscmVjeWNsZSBiaW4gZnVsbA0KMzQsdGVsZXBob255DQozNSxkZXNrdG9wDQozNixvbGQgc2V0dGluZ3MNCjM3LHByb2dyYW0gZ3JvdXAsIHNhbWUgYXMgMjANCjM4LG9sZCBwcmludGVyDQozOSxmb250cw0KNDAsdGFza2JhciBwcm9wZXJ0aWVzDQo0MSxtdXNpYyBjZA0KNDIsdHJlZQ0KNDMsb2xkIGNvbXB1dGVyIGZvbGRlcg0KNDQsZmF2b3JpdGVzDQo0NSxsb2cgb2ZmDQo0NixmaW5kIGluIGZvbGRlcg0KNDcsd2luZG93cyB1cGRhdGUNCjQ4LGxvY2sNCjQ5LGNvbXB1dGVyIGFwcCA/DQo1MCxlbXB0eSAtIGlnbm9yZQ0KNTEsZW1wdHkgLSBpZ25vcmUNCjUyLGVtcHR5IC0gaWdub3JlDQo1MyxlbXB0eSAtIGlnbm9yZQ0KNTQsb2xkIG1pc3RlcnkgZHJpdmUNCjEzMyxmaWxlIHN0YWNrDQoxMzQsZmluZCBmaWxlcw0KMTM1LGZpbmQgY29tcHV0ZXIgZ2x5cGgNCjEzNyxjb250cm9sIHBhbmVsLCBzYW1lIGFzIDIyDQoxMzgscHJpbnRlciBmb2xkZXINCjEzOSxhZGQgcHJpbnRlcg0KMTQwLG5ldHdvcmsgcHJpbnRlcg0KMTQxLHByaW50IHRvIGZpbGUNCjE0MixvbGQgcmVjeWNsZSBiaW4gZnVsbA0KMTQzLG9sZCByZWN5Y2xlIGJpbiBmdWxsIG9mIGZvbGRlcnMNCjE0NCxvbGQgcmVjeWNsZSBiaW4gZnVsbCBvZiBmb2xkZXJzIGFuZCBmaWxlcw0KMTQ1LGNhbid0IGNvcHkgKG92ZXJ3cml0ZT8pIGZpbGUNCjE0Nixtb3ZlIHRvIGZvbGRlcg0KMTQ3LG9sZCByZW5hbWUNCjE0OCxvbGQgc2V0dGluZ3MgY29weQ0KMTUxLGluaSBmaWxlDQoxNTIsdHh0IGZpbGUNCjE1MyxiYXQgZmlsZQ0KMTU0LGRsbCBmaWxlDQoxNTUsZm9udCBmaWxlDQoxNTYsdHJ1ZSB0eXBlIGZvbnQgZmlsZQ0KMTU3LG90aGVyIGZvbnQgZmlsZQ0KMTYwLHJ1biwgc2FtZSBhcyAyNQ0KMTYxLG9sZCBkZWxldGUNCjE2NSxjb3B5IHRvIGRpc2sNCjE2NixlcnJvciBjaGVja2luZw0KMTY3LGRlZnJhZ21lbnQNCjE2OCxwcmludGVyIG9rDQoxNjksbmV0d29yayBwcmludGVyIG9rDQoxNzAscHJpbnRlciBvaywgZmlsZQ0KMTcxLGZpbGUgdHJlZSBzdHJ1Y3R1cmUNCjE3MixuZXR3b3JrIGZvbGRlcg0KMTczLGZhdm9yaXRlcw0KMTc0LG9sZCB3ZWlyZCBmb2xkZXINCjE3NSxuZXR3b3JrIChjb25uZWN0IHRvIGdsb2JlKQ0KMTc2LGFkZCBuZXR3b3JrIGZvbGRlcg0KMTc3LG9sZCBodHQgZmlsZQ0KMTc4LGFkZCBuZXR3b3JrDQoxNzksb2xkIG5ldHdvcmsgdGVybWluYWwgdGhpbmcNCjE4MCxzY3JlZW4gZnVsbA0KMTgxLHNjcmVlbiBlbXB0eQ0KMTgyLGZvbGRlciBvcHRpb25zOiB3aW5kb3cgaW1hZ2Ugd2l0aCB3ZWJ2aWV3DQoxODMsZm9sZGVyIG9wdGlvbnM6IHdpbmRvdyBpbWFnZSB3aXRob3V0IHdlYnZpZXcNCjE4NCxmb2xkZXIgb3B0aW9uczogb3BlbiBpbiBzYW1lIHdpbmRvdw0KMTg1LGZvbGRlciBvcHRpb25zOiBvcGVuIGluIG5ldyB3aW5kb3cNCjE4Nixmb2xkZXIgb3B0aW9uczogY2xpY2sgZmlsZXMgKGxpbmsgc3R5bGUpDQoxODcsZm9sZGVyIG9wdGlvbnM6IGNsaWNrIGZpbGVzIChub3JtYWwgc3R5bGUpDQoxOTEsb2xkIGJpbiBlbXB0eQ0KMTkyLG9sZCBiaW4gZnVsbA0KMTkzLG5ldHdvcmsgZm9sZGVyDQoxOTQsb2xkIGxvZ2luIChrZXlzKQ0KMTk2LGZheA0KMTk3LGZheCBvaw0KMTk4LG5ldHdvcmsgZmF4IG9rDQoxOTksbmV0d29yayBmYXgNCjIwMCxzdG9wDQoyMTAsZm9sZGVyIHNldHRpbmdzDQoyMjAsb2xkIGtleSB1c2Vycw0KMjIxLHNodXRkb3duIChibHVlIGNpcmNsZSkNCjIyMixkdmQgZGlzaw0KMjIzLHNvbWUgZmlsZXMNCjIyNCx2aWRlbyBmaWxlcw0KMjI1LG11c2ljIGZpbGVzDQoyMjYsaW1hZ2UgZmlsZXMNCjIyNyx2YXJpb3VzIG11c2ljL3ZpZGVvIGZpbGVzDQoyMjgsb2xkIG11c2ljIGRpc2sNCjIyOSxodWIgPw0KMjMwLHppcCBkcml2ZQ0KMjMxLGRvd24gb3ZlcmxheQ0KMjMyLGRvd24gb3ZlcmxheSBhZ2Fpbg0KMjMzLG90aGVyIHJlbW92ZWFibGUgbWVkaWEsIHNhbWUgYXMgOA0KMjM0LG5vIGRpc2sgZHJpdmUgZGlzYWJsZWQNCjIzNSxteSBkb2N1bWVudHMNCjIzNixteSBwaWN0dXJlcw0KMjM3LG15IG11c2ljDQoyMzgsbXkgdmlkZW9zDQoyMzksbXNuDQoyNDAsZGVsZXRlICh3ZWJ2aWV3KQ0KMjQxLGNvcHkgKHdlYnZpZXcpDQoyNDIscmVuYW1lICh3ZWJ2aWV3KQ0KMjQzLGZpbGVzICh3ZWJ2aWV3KQ0KMjQ0LGdsb2JlIHcvIGFycm93DQoyNDUscHJpbnRlciBwcmludGluZw0KMjQ2LGdyZWVuIGFycm93ICh3ZWJ2aWV3KQ0KMjQ3LG11c2ljICh3ZWJ2aWV3KQ0KMjQ4LGNhbWVyYQ0KMjQ5LGJvYXJkDQoyNTAsZGlzcGxheSBwcm9wZXJ0aWVzDQoyNTEsbmV0d29yayBpbWFnZXMNCjI1MixwcmludCBpbWFnZXMNCjI1MyxvayBmaWxlICh3ZWJ2aWV3KQ0KMjU0LGJpbiBlbXB0eQ0KMjU1LGdyZWVuIGNvb2wgYXJyb3cgKHdlYnZpZXcpDQoyNTYsbW92ZQ0KMjU3LG5ldHdvcmsgY29ubmVjdGlvbg0KMjU4LG5ldHdvcmsgZHJpdmUgcmVkIHRoaW5nDQoyNTksbmV0d29yayBob21lDQoyNjAsd3JpdGUgY2QgKHdlYnZpZXcpDQoyNjEsY2QgdGhpbmcgKHdlYnZpZXcpDQoyNjIsZGVzdHJveSBjZCAod2VidmlldykNCjI2MyxoZWxwLCBzYW1lIGFzIDI0DQoyNjQsbW92ZSB0byBmb2xkZXIgKHdlYnZpZXcpDQoyNjUsc2VuZCBtYWlsICh3ZWJ2aWV3KQ0KMjY2LG1vdmUgdG8gY2QgKHdlYnZpZXcpDQoyNjcsc2hhcmVkIGZvbGRlcg0KMjY4LGFjY2Vzc2liaWx0eSBvcHRpb25zDQoyNjksdXNlcnMgeHANCjI3MCxzY3JlZW4gcGFsZXR0ZQ0KMjcxLGFkZCBvciByZW1vdmUgcHJvZ3JhbXMNCjI3Mixtb3VzZSBwcmludGVyDQoyNzMsbmV0d29yayBjb21wdXRlcnMNCjI3NCxnZWFyLCBzZXR0aW5ncw0KMjc1LGRyaXZlIHVzZSAocGllY2hhcnQpDQoyNzYsbmV0d29yayBjYWxlbmRlciwgc3luY3JvbmlzZSA/DQoyNzcsbXVzaWMgY3BhbmVsDQoyNzgsYXBwIHNldHRpbmdzDQoyNzksdXNlciB4cCwgc2FtZSBhcyAyNjkNCjI4MSxmaW5kIGZpbGVzDQoyODIsdGFsa2luZyBjb21wdXRlcg0KMjgzLHNjcmVlbiBrZXlib2FyZA0KMjg0LGJsYWNrIHRoaW5neQ0KMjg5LGhlbHAgZmlsZQ0KMjkwLGdvIGFycm93IGllDQoyOTEsZHZkIGRyaXZlDQoyOTIsbXVzaWMrIGNkDQoyOTMsdW5rbm93biBjZA0KMjk0LGNkLXJvbQ0KMjk1LGNkLXINCjI5NixjZC1ydw0KMjk3LGR2ZC1yYW0NCjI5OCxkdmQtcg0KMjk5LHdhbGttYW4NCjMwMCxjYXNzZXRlIGRyaXZlDQozMDEsc21hbGxlciBjYXNzZXRlIGRyaXZlDQozMDIsY2QNCjMwMyxyZWQgdGhpbmcNCjMwNCxkdmQtcm9tDQozMDUsb3RoZXIgcmVtb3ZlYWJsZSBtZWRpYSwgc2FtZSBhcyA4IGFuZCAyMzMNCjMwNixjYXJkcyA/DQozMDcsY2FyZHMgPyAyDQozMDgsY2FyZHMgPyAzDQozMDksY2FtZXJhLCBzYW1lIGFzIGJlZm9yZQ0KMzEwLGNlbGxwaG9uZQ0KMzExLG5ldHdvcmsgcHJpbnRlciBnbG9iZQ0KMzEyLGphenogZHJpdmUNCjMxMyx6aXAgZHJpdmUsIHNhbWUgYXMgYmVmb3JlDQozMTQscGRhDQozMTUsc2Nhbm5lcg0KMzE2LHNjYW5uZXIgYW5kIGNhbWVyYQ0KMzE3LHZpZGVvIGNhbWVyYQ0KMzE4LGR2ZC1ydywgc2FtZSBhcyBiZWZvcmUNCjMxOSxuZXcgZm9sZGVyIChyZWQgdGhpbmcpDQozMjAsbW92ZSB0byBkaXNrICh3ZWJ2aWV3KQ0KMzIxLGNvbnRyb2wgcGFuZWwsIHRoaXJkIHRpbWUNCjMyMixzdGFydCBtZW51IGZhdm9yaXRlcyAoc21hbGxlciBpY29uKQ0KMzIzLHN0YXJ0IG1lbnUgZmluZCAoc21hbGxlciBpY29uKQ0KMzI0LHN0YXJ0IG1lbnUgaGVscCAoc21hbGxlciBpY29uKQ0KMzI1LHN0YXJ0IG1lbnUgbG9nb2ZmIChzbWFsbGVyIGljb24pDQozMjYsc3RhcnQgbWVudSBwcm9ncmFtIGdyb3VwIChzbWFsbGVyIGljb24pDQozMjcsc3RhcnQgbWVudSByZWNlbnQgZG9jdW1lbnRzIChzbWFsbGVyIGljb24pDQozMjgsc3RhcnQgbWVudSBydW4gKHNtYWxsZXIgaWNvbikNCjMyOSxzdGFydCBtZW51IHNodXRkb3duIChzbWFsbGVyIGljb24pDQozMzAsc3RhcnQgbWVudSBjb250cm9sIHBhbmVsKHNtYWxsZXIgaWNvbikNCjMzMSxzdGFydCBtZW51IGxvZ29mZiBvciBzb21ldGhpbmcgKHNtYWxsZXIgaWNvbikNCjMzNyxvbGQgbG9va3VwIHBob25lYm9vaw0KMzM4LHN0b3AsIGFnYWluDQo1MTIsaW50ZXJuZXQgZXhwbG9yZXINCjEwMDEscXVlc3Rpb24NCjEwMDIscHJpbnRlciByZWQgb2sgKHdlYnZpZXcpDQoxMDAzLGRyaXZlIG9rICh3ZWJ2aWV3KQ0KMTAwNCxoZWxwIGZpbGUsIGFnYWluDQoxMDA1LG1vdmUgZmlsZSAod2VidmlldykNCjEwMDYscHJpbnRlciBmaWxlICh3ZWJ2aWV3KQ0KMTAwNyxyZWQgb2sgZmlsZSAod2VidmlldykNCjEwMDgscHJpbnRlciBwYXVzZSAod2VidmlldykNCjEwMDkscHJpbnRlciBwbGF5ICh3ZWJ2aWV3KQ0KMTAxMCxzaGFyZWQgcHJpbnRlciAod2VidmlldykNCjEwMTEsZmF4LCBhZ2Fpbg0KODI0MCxvbGQgbG9nb2ZmDQoxNjcxMCxvbGQgZGVsZXRlDQoxNjcxNSxvbGQgZGVsZXRlDQoxNjcxNyxvbGQgZGVsZXRlDQoxNjcxOCxvbGQgZGVsZXRlDQoxNjcyMSxvbGQgZGVsZXRlDQo=') | ConvertFrom-CSV -Delimiter ',' -Header Idx,Icon
$null = $Shell32_dll_icon_idx
Function New-HTML_Dll_Icons 
{
    [Alias('Create-HTML_Dll_Icons')]
    Param($dllPath)
    If ($null -eq $dllPath)
    {
        Write-Output "specify a dll";
        Return;
    }

    If (! (Test-Path $dllPath))
    {
        Write-Output "$dllPath is not a file";
        Return;
    }

    $filenameWithoutSuffix = [IO.Path]::GetFileNameWithoutExtension($dllPath)

    #region - Shell32_Extract.ps1
        #
        #   https://stackoverflow.com/questions/6872957/how-can-i-use-the-images-within-shell32-dll-in-my-c-sharp-project
        #
        add-type -typeDefinition '

        using System;
        using System.Runtime.InteropServices;

        public class Shell32_Extract {

          [DllImport(
             "Shell32.dll",
              EntryPoint        = "ExtractIconExW",
              CharSet           =  CharSet.Unicode,
              ExactSpelling     =  true,
              CallingConvention =  CallingConvention.StdCall)
          ]

           public static extern int ExtractIconEx(
              string lpszFile          , // Name of the .exe or .dll that contains the icon
              int    iconIndex         , // zero based index of first icon to extract. If iconIndex == 0 and and phiconSmall == null and phiconSmall = null, the number of icons is returnd
              out    IntPtr phiconLarge,
              out    IntPtr phiconSmall,
              int    nIcons
          );

        }
        ';
    #endregion
    #region - User32_DestroyIcon.ps1
        add-type -typeDefinition '

        using System;
        using System.Runtime.InteropServices;

        public class User32_DestroyIcon {

          [DllImport(
             "User32.dll",
              EntryPoint        = "DestroyIcon"
          )]
           public static extern int DestroyIcon(IntPtr hIcon);

        }
        ';
    #endregion

    <#
        Go.ps1
        Param ($dllPath = "$env:SystemRoot\System32\inetcpl.cpl")

        #
        #  Prevent Error
        #    Unable to find type [System.Drawing.Icon]
        #  and
        #    Unable to find type [System.Drawing.Imaging.ImageFormat].
        #
        $null = [Reflection.Assembly]::LoadWithPartialName('System.Drawing');
        $null = [Reflection.Assembly]::LoadWithPartialName('System.Drawing.Imaging');

        $dllPath = "$env:SystemRoot\System32\imageres.dll"

        [System.IntPtr] $phiconSmall = 0
        [System.IntPtr] $phiconLarge = 0

        $nofImages = [Shell32_Extract]::ExtractIconEx($dllPath, -1, [ref] $phiconLarge, [ref] $phiconSmall, 0)

        foreach ($iconIndex in 0 .. ($nofImages-1)) {

            $nofIconsExtracted = [Shell32_Extract]::ExtractIconEx($dllPath, $iconIndex, [ref] $phiconLarge, [ref] $phiconSmall, 1)

            if ($nofIconsExtracted -ne 2) {
                write-error "iconsExtracted = $nofIconsExtracted"
            }

            $iconSmall = [System.Drawing.Icon]::FromHandle($phiconSmall);
            $iconLarge = [System.Drawing.Icon]::FromHandle($phiconLarge);

            $bmpSmall = $iconSmall.ToBitmap()
            $bmpLarge = $iconLarge.ToBitmap()

            $iconIndex_0  = '{0,3:000}' -f $iconIndex

            #
            #  System.Drawing.Image.Save(), without specifying an encoder, stores
            #  the bitmap in png format.
            #
            $bmpLarge.Save("$(get-location)\small-$iconIndex_0.png");
            $bmpLarge.Save("$(get-location)\large-$iconIndex_0.png");

            #
            #  Use System.Drawing.Imaging.ImageFormat to specify a
            #  different format:
            #

            $bmpSmall.Save("$(get-location)\small-$iconIndex_0.bmp", [System.Drawing.Imaging.ImageFormat]::Bmp );
            $bmpLarge.Save("$(get-location)\large-$iconIndex_0.bmp", [System.Drawing.Imaging.ImageFormat]::Bmp );
   
            $bmpSmall.Save("$(get-location)\small-$iconIndex_0.jpg", [System.Drawing.Imaging.ImageFormat]::Jpeg);
            $bmpLarge.Save("$(get-location)\large-$iconIndex_0.jpg", [System.Drawing.Imaging.ImageFormat]::Jpeg);

        }
    #>

    "<html><head>
    <title>Icons in $filenameWithoutSuffix.dll</title></head><body>
       <h1>Icons in $filenameWithoutSuffix.dll</h1>
       These icons were extracted with <a href='https://renenyffenegger.ch/notes/Windows/PowerShell/examples/WinAPI/ExtractIconEx'>PowerShell and the WinAPI function <code>ExtractIconEx</code></a><p>
    <table><tr>" | out-file "$filenameWithoutSuffix.html";

    $null = [Reflection.Assembly]::LoadWithPartialName('System.Drawing');
    $null = [Reflection.Assembly]::LoadWithPartialName('System.Drawing.Imaging');

    [System.IntPtr] $phiconSmall = 0;
    [System.IntPtr] $phiconLarge = 0;

    $nofImages = [Shell32_Extract]::ExtractIconEx($dllPath, -1, [ref] $phiconLarge, [ref] $phiconSmall, 0);
    $nofImages;


    foreach ($iconIndex in 0 .. ($nofImages-1))
    {
        $nofIconsExtracted = [Shell32]::ExtractIconEx($dllPath, $iconIndex, [ref] $phiconLarge, [ref] $phiconSmall, 1)
        $null = $nofIconsExtracted
        $iconLarge = [System.Drawing.Icon]::FromHandle($phiconLarge);

        $bmpLarge  = $iconLarge.ToBitmap()
  
        $iconIndex_0  = '{0,3:000}' -f $iconIndex
        $imgName = "$filenameWithoutSuffix-$iconIndex_0.png";
        $bmpLarge.Save("$(get-location)\$imgName");

        if ($iconIndex -and (! ($iconIndex % 10))) {
        "</tr><tr>" | out-file "$filenameWithoutSuffix.html" -append;
        }
  
  
        "<td>$iconIndex_0</td><td><img src='$imgName'/></td>" | out-file "$filenameWithoutSuffix.html" -append;
  
        $null = [User32_DestroyIcon]::DestroyIcon($phiconSmall);
        $null = [User32_DestroyIcon]::DestroyIcon($phiconLarge);

    }

    "</table></body></html>" | out-file "$filenameWithoutSuffix.html" -append;
}

#region - Call ExtractStringFromDLL()
    add-type -typeDefinition (Dec64 'ICAgIHVzaW5nIFN5c3RlbTsNCiAgICB1c2luZyBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXM7DQogICAgdXNpbmcgU3lzdGVtLlRleHQ7DQoNCiAgICBwdWJsaWMgY2xhc3MgdHE4NF9rcm5sIHsNCg0KICAgICAgW0RsbEltcG9ydCgia2VybmVsMzIuZGxsIiwNCiAgICAgICAgICBTZXRMYXN0RXJyb3IgPSB0cnVlLA0KICAgICAgICAgIENoYXJTZXQgICAgICA9IENoYXJTZXQuQW5zaQ0KICAgICAgICldDQogICAgICAgcHJpdmF0ZSBzdGF0aWMgZXh0ZXJuIEludFB0ciAgICAgICAgICAgICAgTG9hZExpYnJhcnlFeA0KICAgICAgICgNCiAgICAgICAgIFtNYXJzaGFsQXMoVW5tYW5hZ2VkVHlwZS5MUFN0cildc3RyaW5nICBscEZpbGVOYW1lLA0KICAgICAgICAgIEludFB0ciAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhGaWxlLA0KICAgICAgICAgIHVpbnQgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGR3RmxhZ3MNCiAgICAgICApOw0KDQogICAgICBbRGxsSW1wb3J0KCJ1c2VyMzIuZGxsIiAgLA0KICAgICAgICAgIFNldExhc3RFcnJvciA9IHRydWUsDQogICAgICAgICAgQ2hhclNldCAgICAgID0gQ2hhclNldC5BdXRvDQogICAgICAgKV0NCiAgICAgICBwcml2YXRlIHN0YXRpYyBleHRlcm4gaW50ICAgICAgICAgICAgICAgICBMb2FkU3RyaW5nDQogICAgICAgKA0KICAgICAgICAgIEludFB0ciAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhJbnN0YW5jZSwNCiAgICAgICAgICBpbnQgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBJRCwNCiAgICAgICAgICBTdHJpbmdCdWlsZGVyICAgICAgICAgICAgICAgICAgICAgICAgICBscEJ1ZmZlciwNCiAgICAgICAgICBpbnQgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBuQnVmZmVyTWF4DQogICAgICAgKTsNCg0KICAgICAgW0RsbEltcG9ydCgia2VybmVsMzIuZGxsIiwNCiAgICAgICAgICBTZXRMYXN0RXJyb3IgPSB0cnVlKV0NCiAgICAgIFtyZXR1cm46IE1hcnNoYWxBcyhVbm1hbmFnZWRUeXBlLkJvb2wpXQ0KICAgICAgIHByaXZhdGUgc3RhdGljIGV4dGVybiBib29sICAgICAgICAgICAgICAgIEZyZWVMaWJyYXJ5DQogICAgICAgKA0KICAgICAgICAgIEludFB0ciAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhNb2R1bGUNCiAgICAgICApOw0KDQogICAgICBwdWJsaWMgc3RhdGljIHN0cmluZyBFeHRyYWN0U3RyaW5nRnJvbURMTChzdHJpbmcgZmlsZSwgaW50IG51bWJlcikgew0KDQogICAgICAgICAgSW50UHRyIGxpYiA9IExvYWRMaWJyYXJ5RXgoZmlsZSwgbmV3IEludFB0cigwTCksIDMyKTsgLy8gMzIgPSBMT0FEX0xJQlJBUllfQVNfSU1BR0VfUkVTT1VSQ0UNCiAgICAgICAgICBTdHJpbmdCdWlsZGVyIHJlc3VsdCA9IG5ldyBTdHJpbmdCdWlsZGVyKDIwNDgpOw0KICAgICAgICAgIExvYWRTdHJpbmcobGliLCBudW1iZXIsIHJlc3VsdCwgcmVzdWx0LkNhcGFjaXR5KTsNCiAgICAgICAgICBGcmVlTGlicmFyeShsaWIpOw0KDQogICAgICAgICAgcmV0dXJuIHJlc3VsdC5Ub1N0cmluZygpOw0KICAgICAgfQ0KICAgIH0=')
    <#
        Github repository about-PowerShell, path: /examples/WinAPI/ExtractStringFromDLL.ps1
        Using the function:
        The function can now be used to extract a few strings from different DLLs:
            [tq84_krnl]::ExtractStringFromDLL("$env:SystemRoot\system32\Microsoft.Bluetooth.UserService.dll",   102)
            [tq84_krnl]::ExtractStringFromDLL("$env:SystemRoot\system32\shell32.dll"                        , 21799)
            [tq84_krnl]::ExtractStringFromDLL("$env:SystemRoot\system32\input.dll"                          ,  5035)
    #>
#endregion
