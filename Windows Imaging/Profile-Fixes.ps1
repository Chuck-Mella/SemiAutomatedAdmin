    #region - Profile Fixes
        #region - AppxRemove.csv
       ENC64 "3D Builder,Get-AppxPackage *3dbuilder* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Alarms & Clock,Get-AppxPackage *alarms* | Remove-AppxPackage -AllUsers -Verbose,I,I
        AV1 Codec,Get-AppxPackage *AV1VideoExtension* | Remove-AppxPackage -AllUsers -Verbose,I,I
        Calculator,Get-AppxPackage *calculator* | Remove-AppxPackage -AllUsers -Verbose,N,N
        Calendar and Mail,Get-AppxPackage *communicationsapps* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Capture Picker,Get-AppxPackage *CapturePicker* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Clip Champ,Get-AppxPackage *Clipchamp* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Cortana,Get-AppxPackage *Microsoft.549981C3F5F10* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Desktop Installer,Get-AppxProvisionedPackage -Online | ? PackageName -match  *desktopI* | Remove-AppxProvisionedPackage -Online -AllUsers,I,I
        ECApp,Get-AppxPackage *ECApp* | Remove-AppxPackage -AllUsers -Verbose,I,I
        Feedback Hub,Get-AppxPackage *WindowsFeedbackHub* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        GamingApps,Get-AppxPackage *GamingApp* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Get Help app,Get-AppxPackage *GetHelp* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Get Office,Get-AppxPackage *officehub* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Get Started,Get-AppxPackage *getstarted* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        HEIF image support,Get-AppxPackage *HEIFImageExtension* | Remove-AppxPackage -AllUsers -Verbose,I,I
        Maps,Get-AppxPackage *maps* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Microsoft Edge,Get-AppxPackage *MicrosoftEdge* | Remove-AppxPackage -AllUsers -Verbose,N,N
        Microsoft Raw Image Extension,Get-AppxPackage *RawImage* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Microsoft Solitaire Collection,Get-AppxPackage *solitaire* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Microsoft Store,Get-AppxPackage *windowsstore* | Remove-AppxPackage -AllUsers -Verbose,I,I
        Microsoft To-Do,Get-AppxPackage *Todos* | Remove-AppxPackage -AllUsers -Verbose,I,I
        Mixed Reality Portal,Get-AppxPackage *MixedReality* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Movies and TV,Get-AppxPackage *ZuneVideo* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        MS Office,Get-AppxPackage *MicrosoftOfficeHub* | Remove-AppxPackage -AllUsers -Verbose,I,I
        MS Paint,Get-AppxPackage *Paint* | Remove-AppxPackage -AllUsers -Verbose,N,N
        Music app,Get-AppxPackage *ZuneMusic* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        News app,Get-AppxPackage *BingNews* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        News | Sports | Weather apps,Get-AppxPackage *bing* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Notepad,Get-AppxPackage *WindowsNotepad* | Remove-AppxPackage -AllUsers -Verbose,N,N
        OneDrive,Get-AppxPackage *OneDriveSync* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        OneNote,Get-AppxPackage *onenote* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        People,Get-AppxPackage *people* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Photos,Get-AppxPackage *photos* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        PowerAutomate,Get-AppxPackage *PowerAutomateDesktop* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        PowerShell,Get-AppxPackage *PowerShell* | Remove-AppxPackage -AllUsers -Verbose,N,N
        Screen & Sketch/Snipping tool,Get-AppxPackage *ScreenSketch* | Remove-AppxPackage -AllUsers -Verbose,N,N
        Skype,Get-AppxPackage *skype* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Solitaire Collection,Get-AppxPackage *MicrosoftSolitaireCollection* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Sports,Get-AppxPackage *bingsports* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Spotify,Get-AppxPackage *SpotifyAB.SpotifyMusic* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Sticky Notes,Get-AppxPackage *MicrosoftStickyNotes* | Remove-AppxPackage -AllUsers -Verbose,I,I
        Sway,Get-AppxPackage *sway* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Teams/Chat,Get-AppxPackage *Teams* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Voice Recorder,Get-AppxPackage *soundrecorder* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        VP9 Video Extensions,Get-AppxPackage *VP9VideoExtensions* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Weather,Get-AppxPackage *BingWeather* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        WebP image support,Get-AppxPackage *WebpImageExtension* | Remove-AppxPackage -AllUsers -Verbose,I,I
        Widgets,Get-AppxPackage *WebExperience* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Windows Camera,Get-AppxPackage *camera* | Remove-AppxPackage -AllUsers -Verbose,Y,Y
        Windows Terminal,Get-AppxPackage *WindowsTerminal* | Remove-AppxPackage -AllUsers -Verbose,N,N
        Xbox and all related apps,Get-AppxPackage *Xbox* | Remove-AppxPackage -AllUsers -Verbose,I,I
        Xbox Game Callable,Get-AppxPackage *XboxGameCallable* | Remove-AppxPackage -AllUsers -Verbose,I,I
        Xbox Gaming Overlay,Get-AppxPackage *XboxGamingOverlay* | Remove-AppxPackage -AllUsers -Verbose,I,I
        Xbox Speech To Text Overlay,Get-AppxPackage *XboxSpeechToTextOverlay* | Remove-AppxPackage -AllUsers -Verbose,I,I
        Xbox TCUI,Get-AppxPackage *Xbox.TCUI* | Remove-AppxPackage -AllUsers -Verbose,I,I
        Your Phone Companion,Get-AppxPackage *yourphone* | Remove-AppxPackage -AllUsers -Verbose,Y,Y" | ConvertFrom-Csv -Delimiter ',' -Header Application,RemoveCMD,rmvPurple,rmvYellow
        #endregion
        #region - AppxRemoval.ps1
            Function Dec64 { Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b };
            $appData = (Dec64 'M0QgQnVpbGRlcixHZXQtQXBweFBhY2thZ2UgKjNkYnVpbGRlciogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLFksWQ0KICAgICAgICBBbGFybXMgJiBDbG9jayxHZXQtQXBweFBhY2thZ2UgKmFsYXJtcyogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLEksSQ0KICAgICAgICBBVjEgQ29kZWMsR2V0LUFwcHhQYWNrYWdlICpBVjFWaWRlb0V4dGVuc2lvbiogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLEksSQ0KICAgICAgICBDYWxjdWxhdG9yLEdldC1BcHB4UGFja2FnZSAqY2FsY3VsYXRvciogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLE4sTg0KICAgICAgICBDYWxlbmRhciBhbmQgTWFpbCxHZXQtQXBweFBhY2thZ2UgKmNvbW11bmljYXRpb25zYXBwcyogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLFksWQ0KICAgICAgICBDYXB0dXJlIFBpY2tlcixHZXQtQXBweFBhY2thZ2UgKkNhcHR1cmVQaWNrZXIqIHwgUmVtb3ZlLUFwcHhQYWNrYWdlIC1BbGxVc2VycyAtVmVyYm9zZSxZLFkNCiAgICAgICAgQ2xpcCBDaGFtcCxHZXQtQXBweFBhY2thZ2UgKkNsaXBjaGFtcCogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLFksWQ0KICAgICAgICBDb3J0YW5hLEdldC1BcHB4UGFja2FnZSAqTWljcm9zb2Z0LjU0OTk4MUMzRjVGMTAqIHwgUmVtb3ZlLUFwcHhQYWNrYWdlIC1BbGxVc2VycyAtVmVyYm9zZSxZLFkNCiAgICAgICAgRGVza3RvcCBJbnN0YWxsZXIsR2V0LUFwcHhQcm92aXNpb25lZFBhY2thZ2UgLU9ubGluZSB8ID8gUGFja2FnZU5hbWUgLW1hdGNoICAqZGVza3RvcEkqIHwgUmVtb3ZlLUFwcHhQcm92aXNpb25lZFBhY2thZ2UgLU9ubGluZSAtQWxsVXNlcnMsSSxJDQogICAgICAgIEVDQXBwLEdldC1BcHB4UGFja2FnZSAqRUNBcHAqIHwgUmVtb3ZlLUFwcHhQYWNrYWdlIC1BbGxVc2VycyAtVmVyYm9zZSxJLEkNCiAgICAgICAgRmVlZGJhY2sgSHViLEdldC1BcHB4UGFja2FnZSAqV2luZG93c0ZlZWRiYWNrSHViKiB8IFJlbW92ZS1BcHB4UGFja2FnZSAtQWxsVXNlcnMgLVZlcmJvc2UsWSxZDQogICAgICAgIEdhbWluZ0FwcHMsR2V0LUFwcHhQYWNrYWdlICpHYW1pbmdBcHAqIHwgUmVtb3ZlLUFwcHhQYWNrYWdlIC1BbGxVc2VycyAtVmVyYm9zZSxZLFkNCiAgICAgICAgR2V0IEhlbHAgYXBwLEdldC1BcHB4UGFja2FnZSAqR2V0SGVscCogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLFksWQ0KICAgICAgICBHZXQgT2ZmaWNlLEdldC1BcHB4UGFja2FnZSAqb2ZmaWNlaHViKiB8IFJlbW92ZS1BcHB4UGFja2FnZSAtQWxsVXNlcnMgLVZlcmJvc2UsWSxZDQogICAgICAgIEdldCBTdGFydGVkLEdldC1BcHB4UGFja2FnZSAqZ2V0c3RhcnRlZCogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLFksWQ0KICAgICAgICBIRUlGIGltYWdlIHN1cHBvcnQsR2V0LUFwcHhQYWNrYWdlICpIRUlGSW1hZ2VFeHRlbnNpb24qIHwgUmVtb3ZlLUFwcHhQYWNrYWdlIC1BbGxVc2VycyAtVmVyYm9zZSxJLEkNCiAgICAgICAgTWFwcyxHZXQtQXBweFBhY2thZ2UgKm1hcHMqIHwgUmVtb3ZlLUFwcHhQYWNrYWdlIC1BbGxVc2VycyAtVmVyYm9zZSxZLFkNCiAgICAgICAgTWljcm9zb2Z0IEVkZ2UsR2V0LUFwcHhQYWNrYWdlICpNaWNyb3NvZnRFZGdlKiB8IFJlbW92ZS1BcHB4UGFja2FnZSAtQWxsVXNlcnMgLVZlcmJvc2UsTixODQogICAgICAgIE1pY3Jvc29mdCBSYXcgSW1hZ2UgRXh0ZW5zaW9uLEdldC1BcHB4UGFja2FnZSAqUmF3SW1hZ2UqIHwgUmVtb3ZlLUFwcHhQYWNrYWdlIC1BbGxVc2VycyAtVmVyYm9zZSxZLFkNCiAgICAgICAgTWljcm9zb2Z0IFNvbGl0YWlyZSBDb2xsZWN0aW9uLEdldC1BcHB4UGFja2FnZSAqc29saXRhaXJlKiB8IFJlbW92ZS1BcHB4UGFja2FnZSAtQWxsVXNlcnMgLVZlcmJvc2UsWSxZDQogICAgICAgIE1pY3Jvc29mdCBTdG9yZSxHZXQtQXBweFBhY2thZ2UgKndpbmRvd3NzdG9yZSogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLEksSQ0KICAgICAgICBNaWNyb3NvZnQgVG8tRG8sR2V0LUFwcHhQYWNrYWdlICpUb2RvcyogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLEksSQ0KICAgICAgICBNaXhlZCBSZWFsaXR5IFBvcnRhbCxHZXQtQXBweFBhY2thZ2UgKk1peGVkUmVhbGl0eSogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLFksWQ0KICAgICAgICBNb3ZpZXMgYW5kIFRWLEdldC1BcHB4UGFja2FnZSAqWnVuZVZpZGVvKiB8IFJlbW92ZS1BcHB4UGFja2FnZSAtQWxsVXNlcnMgLVZlcmJvc2UsWSxZDQogICAgICAgIE1TIE9mZmljZSxHZXQtQXBweFBhY2thZ2UgKk1pY3Jvc29mdE9mZmljZUh1YiogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLEksSQ0KICAgICAgICBNUyBQYWludCxHZXQtQXBweFBhY2thZ2UgKlBhaW50KiB8IFJlbW92ZS1BcHB4UGFja2FnZSAtQWxsVXNlcnMgLVZlcmJvc2UsTixODQogICAgICAgIE11c2ljIGFwcCxHZXQtQXBweFBhY2thZ2UgKlp1bmVNdXNpYyogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLFksWQ0KICAgICAgICBOZXdzIGFwcCxHZXQtQXBweFBhY2thZ2UgKkJpbmdOZXdzKiB8IFJlbW92ZS1BcHB4UGFja2FnZSAtQWxsVXNlcnMgLVZlcmJvc2UsWSxZDQogICAgICAgIE5ld3MgfCBTcG9ydHMgfCBXZWF0aGVyIGFwcHMsR2V0LUFwcHhQYWNrYWdlICpiaW5nKiB8IFJlbW92ZS1BcHB4UGFja2FnZSAtQWxsVXNlcnMgLVZlcmJvc2UsWSxZDQogICAgICAgIE5vdGVwYWQsR2V0LUFwcHhQYWNrYWdlICpXaW5kb3dzTm90ZXBhZCogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLE4sTg0KICAgICAgICBPbmVEcml2ZSxHZXQtQXBweFBhY2thZ2UgKk9uZURyaXZlU3luYyogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLFksWQ0KICAgICAgICBPbmVOb3RlLEdldC1BcHB4UGFja2FnZSAqb25lbm90ZSogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLFksWQ0KICAgICAgICBQZW9wbGUsR2V0LUFwcHhQYWNrYWdlICpwZW9wbGUqIHwgUmVtb3ZlLUFwcHhQYWNrYWdlIC1BbGxVc2VycyAtVmVyYm9zZSxZLFkNCiAgICAgICAgUGhvdG9zLEdldC1BcHB4UGFja2FnZSAqcGhvdG9zKiB8IFJlbW92ZS1BcHB4UGFja2FnZSAtQWxsVXNlcnMgLVZlcmJvc2UsWSxZDQogICAgICAgIFBvd2VyQXV0b21hdGUsR2V0LUFwcHhQYWNrYWdlICpQb3dlckF1dG9tYXRlRGVza3RvcCogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLFksWQ0KICAgICAgICBQb3dlclNoZWxsLEdldC1BcHB4UGFja2FnZSAqUG93ZXJTaGVsbCogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLE4sTg0KICAgICAgICBTY3JlZW4gJiBTa2V0Y2gvU25pcHBpbmcgdG9vbCxHZXQtQXBweFBhY2thZ2UgKlNjcmVlblNrZXRjaCogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLE4sTg0KICAgICAgICBTa3lwZSxHZXQtQXBweFBhY2thZ2UgKnNreXBlKiB8IFJlbW92ZS1BcHB4UGFja2FnZSAtQWxsVXNlcnMgLVZlcmJvc2UsWSxZDQogICAgICAgIFNvbGl0YWlyZSBDb2xsZWN0aW9uLEdldC1BcHB4UGFja2FnZSAqTWljcm9zb2Z0U29saXRhaXJlQ29sbGVjdGlvbiogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLFksWQ0KICAgICAgICBTcG9ydHMsR2V0LUFwcHhQYWNrYWdlICpiaW5nc3BvcnRzKiB8IFJlbW92ZS1BcHB4UGFja2FnZSAtQWxsVXNlcnMgLVZlcmJvc2UsWSxZDQogICAgICAgIFNwb3RpZnksR2V0LUFwcHhQYWNrYWdlICpTcG90aWZ5QUIuU3BvdGlmeU11c2ljKiB8IFJlbW92ZS1BcHB4UGFja2FnZSAtQWxsVXNlcnMgLVZlcmJvc2UsWSxZDQogICAgICAgIFN0aWNreSBOb3RlcyxHZXQtQXBweFBhY2thZ2UgKk1pY3Jvc29mdFN0aWNreU5vdGVzKiB8IFJlbW92ZS1BcHB4UGFja2FnZSAtQWxsVXNlcnMgLVZlcmJvc2UsSSxJDQogICAgICAgIFN3YXksR2V0LUFwcHhQYWNrYWdlICpzd2F5KiB8IFJlbW92ZS1BcHB4UGFja2FnZSAtQWxsVXNlcnMgLVZlcmJvc2UsWSxZDQogICAgICAgIFRlYW1zL0NoYXQsR2V0LUFwcHhQYWNrYWdlICpUZWFtcyogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLFksWQ0KICAgICAgICBWb2ljZSBSZWNvcmRlcixHZXQtQXBweFBhY2thZ2UgKnNvdW5kcmVjb3JkZXIqIHwgUmVtb3ZlLUFwcHhQYWNrYWdlIC1BbGxVc2VycyAtVmVyYm9zZSxZLFkNCiAgICAgICAgVlA5IFZpZGVvIEV4dGVuc2lvbnMsR2V0LUFwcHhQYWNrYWdlICpWUDlWaWRlb0V4dGVuc2lvbnMqIHwgUmVtb3ZlLUFwcHhQYWNrYWdlIC1BbGxVc2VycyAtVmVyYm9zZSxZLFkNCiAgICAgICAgV2VhdGhlcixHZXQtQXBweFBhY2thZ2UgKkJpbmdXZWF0aGVyKiB8IFJlbW92ZS1BcHB4UGFja2FnZSAtQWxsVXNlcnMgLVZlcmJvc2UsWSxZDQogICAgICAgIFdlYlAgaW1hZ2Ugc3VwcG9ydCxHZXQtQXBweFBhY2thZ2UgKldlYnBJbWFnZUV4dGVuc2lvbiogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLEksSQ0KICAgICAgICBXaWRnZXRzLEdldC1BcHB4UGFja2FnZSAqV2ViRXhwZXJpZW5jZSogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLFksWQ0KICAgICAgICBXaW5kb3dzIENhbWVyYSxHZXQtQXBweFBhY2thZ2UgKmNhbWVyYSogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLFksWQ0KICAgICAgICBXaW5kb3dzIFRlcm1pbmFsLEdldC1BcHB4UGFja2FnZSAqV2luZG93c1Rlcm1pbmFsKiB8IFJlbW92ZS1BcHB4UGFja2FnZSAtQWxsVXNlcnMgLVZlcmJvc2UsTixODQogICAgICAgIFhib3ggYW5kIGFsbCByZWxhdGVkIGFwcHMsR2V0LUFwcHhQYWNrYWdlICpYYm94KiB8IFJlbW92ZS1BcHB4UGFja2FnZSAtQWxsVXNlcnMgLVZlcmJvc2UsSSxJDQogICAgICAgIFhib3ggR2FtZSBDYWxsYWJsZSxHZXQtQXBweFBhY2thZ2UgKlhib3hHYW1lQ2FsbGFibGUqIHwgUmVtb3ZlLUFwcHhQYWNrYWdlIC1BbGxVc2VycyAtVmVyYm9zZSxJLEkNCiAgICAgICAgWGJveCBHYW1pbmcgT3ZlcmxheSxHZXQtQXBweFBhY2thZ2UgKlhib3hHYW1pbmdPdmVybGF5KiB8IFJlbW92ZS1BcHB4UGFja2FnZSAtQWxsVXNlcnMgLVZlcmJvc2UsSSxJDQogICAgICAgIFhib3ggU3BlZWNoIFRvIFRleHQgT3ZlcmxheSxHZXQtQXBweFBhY2thZ2UgKlhib3hTcGVlY2hUb1RleHRPdmVybGF5KiB8IFJlbW92ZS1BcHB4UGFja2FnZSAtQWxsVXNlcnMgLVZlcmJvc2UsSSxJDQogICAgICAgIFhib3ggVENVSSxHZXQtQXBweFBhY2thZ2UgKlhib3guVENVSSogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLEksSQ0KICAgICAgICBZb3VyIFBob25lIENvbXBhbmlvbixHZXQtQXBweFBhY2thZ2UgKnlvdXJwaG9uZSogfCBSZW1vdmUtQXBweFBhY2thZ2UgLUFsbFVzZXJzIC1WZXJib3NlLFksWQ==') | ConvertFrom-Csv -Delimiter ',' -Header Application,RemoveCMD,rmvPurple,rmvYellow

            #'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge' 'SearchSuggestEnabled' 'DWORD' 'Value 0' # 1 to enable


            #; Created by: Shawn Brink
            #; Created on: July 30th 2018
            #; Tutorial: https://www.tenforums.com/tutorials/115069-enable-disable-autofill-microsoft-edge-windows-10-a.html


            [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main]
            "Use FormSuggest"="no"

            $TIC=(Get-ItemProperty 'HKCU:\Control Panel\Desktop' TranscodedImageCache -ErrorAction Stop).TranscodedImageCache

            [System.Text.Encoding]::Unicode.GetString($TIC) -replace '(.+)([A-Z]:[0-9a-zA-Z\\])+','$2'


            Get-ItemProperty "hkcu:\Control Panel\Desktop"| Select WallPaper





            $regKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            # create the key if it doesn't already exist
            if (!(Test-Path -Path $regKey)) {
               $null = New-Item -Path $regKey
            }

            # now set the registry entry
            Set-ItemProperty -Path $regKey -Name LockScreenImage -value "C:\Custom-Folder\wallpaper.jpg"
        #endregion
        #region - Testscript.bat
            <#
                I wish I could take credit for the creation of this file but not my brainwork on this one.

                Below is the content of the .bat file we run and it works for Windows 8 and 10. Copy all the text into a file and name it what you like using a .bat extension. The only thing you need to do is enter the name of the profile you will use to copy over the default profile at the end of the line:      set PROFILE=

                @echo off
                rem 00000000000000000000000000000000000000000000000000000000000000000000000000
                rem  SCRIPT NAME: Update Default User Profile.cmd
                rem      VERSION: 3.0
                rem  DISCRIPTION: Copies the chosen profile to the default user profile then
                rem               removes printers from defautl user's registry in Windows 7.
                rem               Must right click script and run as administrator!
                rem       AUTHOR: Ben Stefan, John McFadden, Karolyn Hannam, Christine Schilling
                rem         DATE: 4/4/2013
                rem 00000000000000000000000000000000000000000000000000000000000000000000000000
                :selectprofile
                cls
                echo / / / / / / / / / / / / / / / / / / / / / / / / / / / /
                echo               Win8 Profile Copy Script
                echo / / / / / / / / / / / / / / / / / / / / / / / / / / / /
                echo Press 1 to continue
                echo Press 2 to cancel

                echo.
                set PROFILE=
                choice /c 12
                if errorlevel 3 set PROFILE=localuser
                if errorlevel 2 goto enderror
            #>
            $trgProfile = 'localuser'
            Test-Path "C:\Users\$trgProfile"
            <#
                if not exist "C:\Users\%PROFILE%" echo ERROR - The Selected Profile Does Not Exist! && goto enderror

                :confirmprofile
                cls
                echo / / / / / / / / / / / / / / / / / / / / / / / / / / / /
                echo               Win8 Profile Copy Script
                echo / / / / / / / / / / / / / / / / / / / / / / / / / / / /
                echo Copy C:\Users\%PROFILE%\ to C:\Users\Default\ ?
                echo.
                choice /c YN
                if errorlevel 2 goto enderror
                if errorlevel 1 goto backupdefaultprofile

                :backupdefaultprofile
                attrib -h "C:\Users\Default"
                if exist "C:\Users\Default_Backup" rmdir /s /q "C:\Users\Default_Backup"
                ping 127.0.0.1 -n 6 -w 1000 > nul
                if exist "C:\Users\Default_Backup" rmdir /s /q "C:\Users\Default_Backup"
                ping 127.0.0.1 -n 6 -w 1000 > nul
                if exist "C:\Users\Default_Backup" echo ERROR - Removal of old Backup Folder Failed! && goto enderror
                rename "C:\Users\Default" "Default_Backup"
                if not exist "C:\Users\Default_Backup" echo ERROR - Backup Failed! && goto enderror
                echo.
                echo Existing Default Profile Successfully Backed Up
                echo.
                ping 127.0.0.1 -n 6 -w 1000 > nul

                :copyinstallerprofile
                md "C:\Users\Default"
                xcopy "C:\Users\%PROFILE%\*.*" "C:\Users\Default" /e /c /h /k /y
                if exist "C:\Users\Default\AppData\Local\Packages" rmdir /s /q "C:\Users\Default\AppData\Local\Packages"
                if exist "C:\Users\Default\AppData\Local\microsoft\Windows\Temporary Internet Files" rmdir /s /q "C:\Users\Default\AppData\Local\microsoft\Windows\Temporary Internet Files"
                if exist "C:\Users\Default\AppData\Local\Temp" Del /s /q "C:\Users\Default\AppData\Local\temp"\*.*
                if exist "C:\Users\Default\AppData\Local\microsoft\Windows\UsrClass.dat" del /s /q /aa "C:\Users\Default\AppData\Local\microsoft\Windows\UsrClass.dat"
                :end
                echo.
                echo Script Completed Successfully . . .
                echo.
                pause
                goto endnow

                :enderror
                echo.
                echo Script Terminated with Errors . . .
                echo.
                pause
                goto endnow

                :endnow
                exit
            #>
        #endregion
    #endregion
