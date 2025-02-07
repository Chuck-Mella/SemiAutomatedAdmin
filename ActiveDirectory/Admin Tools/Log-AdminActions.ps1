### FIX ### FIX ### FIX ### # $originalcode = (Dec64 'QEVDSE8gT0ZGDQONCjpWQVJJQUJMRVMNCg0KCVJFTSBHZXQgdGhliGNlcnJlbnQgZGF0ZSBhbmQgc2F2ZSBpdCB0byB0aGUgJWRhdGUliHZhcmlhYmxlDQoJRk9SIC9GICJUT0tFTlM9MSogREVMSUlTPSAiiCUlQSBJTiAoJ0RBVEUVVCcpiERPIFNFVCBDREFURT0lJUINCglGT1IgL0YgilRPS0VOUz0yLTQgREVMSUlTPS8giiAlJUEgSU4gKCdEQVRFIC9UJykgRE8gKFNFVCBkYXRlPSUlQykNCg0KCVNFVCBMT0dGSUXFPSJCXGFkLWVhc3RcQUQtSVRCTWFpbnRlbmFuY2VMb2dzXCVkYXRlJV8lY29tcHV0ZXJUYWllJS5jc3YiDQONCjpDT0XPUg0KDQOJUkVNIFNldHRpbmcgY29sb3IgdG8gRlJFRU4NCg0KCWNvbG9yiDBhDQoNCjpGSUXFQ0hFQ0sNCg0KCVJFTSBBZGRpbmcgaGVhZGVycyB0byBuZXdseSBjcmVhdGVkiGXVZyBmaWxlDQoJSUYgRVhJU1QgJWXVZ2ZpbGUliChHT1RPIEJFR0lOKSBFTFNFIEdPVE8gSEVBREVSDQONCjpiRUFERVINCg0KCUVDSE8gREFURSXUSUlFLFVTRVIsUllTVEVNLE1YIFBlcmzvcmllZCXNWCBEZXNjcmlwdGlvbixNWCBUZWNobmljaWFULEVzY29ydCXFCXVpcGllbnQgPiAlbG9nZmlsZSUNCg0KOkJFR0lODQOJQ0XTDQOJUkVNIFByb21wdGluzyBlc2VyiGZvciBpbnBldA0KCVNFVCAVCCBNWFBlcmzvcmllZD1FbnRlciBNWCBQZXJmb3JtZWQ6DQoJU0VUIC9WIElYRGVzY3JpcHRpb249RW50ZXIgTVggRGVzY3JpcHRpb246DQoJU0VUIC9wiElYVGVjaG5pY21hbj1FbnRlciBNWCBUZWNobmljaWFuOg0KCVNFVCAVCCBFc2NvcnQ9RW50ZXIgRXNjb3J00g0KCVNFVCAVCCBFCXVpcGllbnQ9RW50ZXIgZXFlaxBtZW50IHJlbW92ZWQgb3IgcmVwbGFjZWQ6DQoJDQoJRUNITyAlY2RhdGUlLCV0aWllOn4wLDilOiVOaWllOn4zLDilLCVlc2VybmFtZSUSJWNvbXBldGVybmFtZSUSJUlYUGVyZm9ybWVkJSwlTVhEZXNjcmlwdGlvbiUsJUlYVGVjaG5pY2lhbiUsJUVZY29ydCUsJUVxdWlwbWVudCUgPj4gJWXVZ2ZpbGUlDQONCjpFTkQNCg0KCWV4aXQ=')
#region - Form Timer for admin script
    # add action to indicate time and 
    # Creating the form object
        $form = New-Object System.Windows.Forms.Form
        $form.Text = "System warning"
        $form.Size = New-Object System.Drawing.Size(300, 250)
        $form.StartPosition = "CenterScreen"

    # ... (Other form setup code)

    # Create a timer to track inactivity
        $Timer = New-Object System.Windows.Forms.Timer
        $Timer.Interval = 30 * 60 * 1000  # 30 minutes in milliseconds
        $Timer.Add_Tick({
            # Close the form after the specified inactivity period
            $form.Close()
        })
        $Timer.Start()

    # Show the form
    $result = $form.ShowDialog()

    # Dispose of the form and timer
    $form.Dispose()
    $Timer.Dispose()

    #OR
    Function ClearAndClose()
    {
        $Timer.Stop(); 
        $Form.Close(); 
        $Form.Dispose();
        $Timer.Dispose();
        $Script:CountDown=5
    }

    Function Button_Click()
    {
        ClearAndClose
    }

    Function Timer_Tick()
    {
        $Label.Text = "Your system will reboot in $Script:CountDown seconds"
         if ($Script:CountDown -lt 0)
         {
            ClearAndClose
         }
    }
#endregion
#region - Initialize the form.
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $Form = New-Object system.Windows.Forms.Form
    $Form.Text = "Attention redémarrage!!"
    $Form.Size = New-Object System.Drawing.Size(250,100)
    $Form.StartPosition = "CenterScreen"
    $Form.Topmost = $True

    $Label = New-Object System.Windows.Forms.Label
    $Label.AutoSize = $true
    $Label.Location = New-Object System.Drawing.Size(20,5)

    $Button = New-Object System.Windows.Forms.Button
    $Button.Location = New-Object System.Drawing.Size(55,35)
    $Button.Size = New-Object System.Drawing.Size(120,23)
    $Button.Text = "STOP"
    $Button.DialogResult=[System.Windows.Forms.DialogResult]::OK

    $Timer = New-Object System.Windows.Forms.Timer
    $Timer.Interval = 1000

    $Form.Controls.Add($Label)
    $Form.Controls.Add($Button)

    $Script:CountDown = 6

    $Button.Add_Click({Button_Click})
    $Timer.Add_Tick({ Timer_Tick})

    $Timer.Start()
    $Form.ShowDialog()
#endregion
#region - Set form parameeters and launch the for.
    $Params = @{} | select Date,Time,LogFile,USER,SYSTEM,'MX Performed','MX Description','MX Technician',Escort,Equipment
        $Params.Date = Get-Date -f yyyy-MM-dd
        $Params.Time = Get-Date -f HH:mm:ss
        $Params.LogFile = '\\<LOGSERVER>\log-AdmAction$\LoginTracking.csv'
        $Params.USER = $env:userName
        $Params.SYSTEM = (& HostName)
    # Admin check
        $admcheck = [bool](([ADSISEARCHER]"samaccountname=$($env:USERNAME)").Findone().Properties.memberof -match '(AD-East Admins|AD-West Admins|Domain Admins)')
        If ($admcheck -ne $true){ EXIT }
    # SYSTEM TEST
        $sysTest = Get-wmiobject -class win32_operatingsystem | select -Exp ProductType
        If ($sysTest -eq 1){ EXIT }
        function AdminForm
        {
            #region Import the Assemblies
                $null = [reflection.assembly]::loadwithpartialname("system.Drawing")
                $null = [reflection.assembly]::loadwithpartialname("System.windows.Forms")
            #endregion
            #region Generated Form Objects
                $Admin_MX = New-object System.windows.Forms.Form
                $Admin_MX.TopMost = 1
                # create Lables
                    'lbl_Equip','lbl_Escort','lbl_MXTech','lbl_MXDesc','lbl_MXLabor','lbl_MXTitle','lbl_logFile','lbl_system','lbl_user','lbl_Time','lbl_Date','lbl_Title' | 
                        %{ New-variable -Name $_ -value (New-Object system.windows.Forms.Label ) }
                # create Textboxes
                    'txt_Equip','txt_Escort','txt_MXDesc','txt_MXTech','txt_MXLabor','txt_logFile','txt_System','txt User','txt~Time','txt_Date' |
                        %{ New-variable -Name $_ -value (New-object System.Windows.Forms.TextBox) }
                # create Buttons
                    $btn_OK = New-object System.windows.Forms.Button
                # create Misc
                    # $listBox1 = New-object system.windows.Forms.ListBox
                    # $comboBox1 = New-object system.windows.Forms.comboBox
                $InitialFormwindowstate = New-object System.Windows.Forms.FormWindowState
            #endregion Generated Form Objects
            #region Generated Event script Blocks
                #Provide custom code for events specified in PrimalForms.
                    $btn_OK_Onclick = { $Admin_Mx.close() }
                    $handler_label5_Click = { <# TODO: Place custom script here#> }
                    $handler_txt_MXLabor_Textchanged = { $Params.'MX Performed' = $txt_MXLabor.Text }
                    $handler_txt_MXDesc_Textchanged = { $Params.'MX Description' = $txt_MXDesc.Text } 
                    $handler_txt_MXTech_Textchanged = { $Params.'MX Technician' = $txt_MXTech.Text }
                    $handler_txt_Escort_Textchanged = { $Params.Escort = $txt_Escort.Text }
                    $handler_txt_Equip_Textchanged = { $Params.Equipment = $txt_Equip.Text }
                    $handler_Admin_Load = { <#TODO: Place custom script here#> }
                    $OnLoadForm_StateCorrection = {
                        # correct the initial state of the form to prevent the .Net maximized form issue
                        $Admin_Mx.windowstate = $InitialFormwindowstate
                        }
            #endregion
            #region Generated Form code
                $Admin_MX.Backcolor = [system.Drawing.color]::FromArgb(255,240,240,240)
                $system_Drawing_size = New-Object System.Drawing.Size
                $System_Drawing_Size.Height = 635
                $System_Drawing_size.width = 437
                $Admin_MX.Clientsize = $system_Drawing_Size
                $Admin_MX.DataBindings.DefaultDataSourceUpdateMode = 0
                $Admin_MX.MaximizeBox = $False
                $Admin_MX.MinimizeBox = $False
                $Admin_MX.Name = "Admin MX"
                $Admin_MX.Text = "Admin MX"
                $Admin_MX.add_Load($handler_Admin_Load)

                $lbl_Title.DataBindings.DefaultDataSourceUpdateMode = 0
                $lbl_Title.Font = New-object System.Drawing.Font("Microsoft sans serif",12,3,3,0)
                $system_Drawing_Point = New-Object System.Drawing.Point
                $System_Drawing_Point.x = 55
                $System_Drawing_Point.Y = 29
                $lbl_Title.Location = $system_Drawing_Point
                $lbl_Title.Name = "lbl_Title"
                $lbl_Title.RightToLeft = 1
                $System_Drawing_Size = New-object System.Drawing.size
                $System_Drawing_Size.Height = 23
                $System_Drawing_size.width = 320
                $lbl_Title.size = $system_Drawing_size
                $lbl_Title.Tabrndex = 0
                $lbl_Title.Text = "Admin Maintenance Log"
                $lbl_Title.TextAlign = 2
                $Admin_MX.Controls.Add($lbl_Title)

                $lbl_MXTitle.DataBindings.DefaultDataSourceUpdateMode = 0
                $lbl_MXTitle.Font = New-Object System.Drawing.Font("Microsoft sans serif",11.25,3,3,0)
                $System_Drawing_Point = New-object System.Drawing.Point
                $system_Drawing_Point.x = 119
                $System_Drawing_Point.Y = 212
                $lbl_MXTitle.Location = $system_Drawing_Point
                $lbl_MXTitle.Name = "lbl_MXTitle"
                $System_Drawing_size = New-object System.Drawing.Size
                $System_Drawing_Size.Height = 31
                $System_Drawin9_Size.Width = 203
                $lbl_MXTitle.Slze = $System_Drawing_size
                $lbl_MXTitle.Tabrndex = 11
                $lbl_MXTitle.Text = "Maintenance Action (MX)"
                $Admin_Mx.controls.Add( $lbl_MXTitle)
            #endregion
            #region OK Button
                $btn_OK.DataBindings.DefaultDataSourceUpdateMode = 0
                $System_Drawing_Point = New-Object System.Drawing.Point
                $System_Drawing_Point.x = 164
                $System_Drawing_Point.Y = 586
                $btn_OK.Location = $system_Drawing_Point
                $btn_OK.Name = "button!"
                $System_Drawing_size = New-Object System.Drawing.Size
                $System_Drawing_Size.Height = 37
                $System_Drawing_size.width = 105
                $btn_OK.Size = $system_Drawing_Size
                $btn_OK.Tabrndex = 0
                $btn_OK.Text = "OK"
                $btn_OK.UsevisualstyleBackcolor = $True
                $btn_OK.add_click($btn_OK_Onclick)
                $Admin_MX.Controls.Add( $btn_OK)
            #endregion
            #region MX Equipment
                $lbl_Equip.DataBindings.DefaultDataSourceUpdateMode = 0
                $System_Drawing_Point = New-Object System.Drawing.Point
                $System_Drawing_Point.X = 39
                $System_Drawing_Point.Y = 426
                $lbl_Equip.Location = $system_Drawing_Point
                $lbl_Equip.Name = "lbl_Equip"
                $system_Drawing_size = New-object System.Drawing.Size
                $system_Drawing_size.Height = 21
                $system_Drawing_size.width = 179
                $lbl_Equip.size = $system_Drawing_size
                $lbl_Equip.Tabrndex = 16
                $lbl_Equip.Text = "Equipment Removed or Replaced"
                $Admin_MX.Controls.Add($lbl_Equip)
                $txt_Equip.DataBindings.DefaultDataSourceUpdateMode = 0
                $System_Drawing_Point = New-object System.Drawing.Point
                $system_Drawing_Point.x = 39
                $system_Drawing_Point.Y = 450
                $txt_Equip.Location = $System_Drawing_Point
                $txt_Equip.Multiline = $True
                $txt_Equip.Name = "txt_Equip"
                $System_Drawing_size = New-Object System.Drawing.size
                $system_Drawing_size.Height = 124
                $system_Drawing_size.width = 354
                $txt_Equip.Size = $System_Drawing_size
                $txt_Equip.Tabrndex = 5
                $txt_Equip.Text = "N/A"
                $txt_Equip.add_Textchanged($handler_txt_Equip_Textchanged)
                $Admin_Mx.controls.Add($txt_Equip)
            #endregion
            #region MX Escort
                $lbl_Escort.DataBindings.DefaultDataSourceUpdateMode = 0
                $System_Drawing_Point = New-object System.Drawing.Point
                $System_Drawing_Point.x = 39
                $system_Drawing_Point.Y = 363
                $lbl_Escort.Location = $System_Drawing_Point
                $lbl_Escort.Name = "lbl_Escort"
                $system_Drawing_size = New-Object System.Drawing.Size
                $system_Drawing_Size.Height = 21
                $system_Drawing_size.width = 103
                $lbl_Escort.Size = $System_Drawing_size
                $lbl_Escort.Tabrndex = 15
                $lbl_Escort.Text = "Escort (Vendor)"
                $Admin_Mx.controls.Add($lbl_Escort)
                $txt_Escort.DataBindings.DefaultDataSourceUpdateMode = 0
                $system_Drawing_Point = New-Object System.Drawing.Point
                $system_Drawing_Point.x = 42
                $System_Drawing_Point.Y = 387
                $txt_Escort.Location = $system_Drawing_Point
                $txt_Escort.Name = "txt_Escort"
                $system_Drawing_Size = New-Object System.Drawing.size
                $system_Drawing_size.Height = 20
                $system_Drawing_size.width = 136
                $txt_Escort.size = $System_Drawing_size
                $txt_Escort.Tabrndex = 4
                $txt_Escort.Text = "N/A"
                $txt_Escort.add_Textchanged($handler_txt_Escort_Textchanged)
                $Admin_Mx.controls.Add($txt_Escort)
            #endregion
            #region MX Description
                $lbl_MXDesc.DataBindings.DefaultDataSourceUpdateMode = 0
                $system_Drawing_Point = New-Object System.Drawing.Point
                $System_Drawing_Point.X = 195
                $system_Drawing_Point.Y = 289
                $lbl_MXDesc.Location = $System_Drawing_Point
                $lbl_MXDesc.Name = "lbl_MXDesc"
                $System_Drawing_Size = New-Object System.Drawing.Size
                $System_Drawing_Size.Height = 24
                $System_Drawing_Size.width = 87
                $lbl_MXDesc.size = $System_Drawing_size
                $lbl_MXDesc.Tabrndex = 13
                $lbl_MXDesc.Text = "MX Description"
                $Admin_Mx.controls.Add($lbl_MXDesc)
                $txt_MXDesc.DataBindings.DefaultDataSourceUpdateMode = 0
                $System_Drawing_Point = New-Object System.Drawing.Point
                $System_Drawing_Point.X = 195
                $System_Drawing_Point.Y = 314
                $txt_MXDesc.Location = $System_Drawing_Point
                $txt_MXDesc.Multiline = $True
                $txt_MXDesc.Name = "txt_MXDesc"
                $System_Drawing_size = New-Object System.Drawing.Size
                $system_Drawing_size.Height = 98
                $System_Drawing_size.width = 198
                $txt_MXDesc.size = $system_Drawing_size
                $txt_MXDesc.Tabrndex = 3
                $txt_MXDesc.Text = "N/ A"
                $txt_MXDesc.add_Textchanged($handler_txt_MXDesc_Textchanged)
                $Admin_Mx.controls.Add($txt_MXDesc)
            #endregion
            #region MX Technician
                $lbl_MXTech.DataBindings.DefaultDataSourceUpdateMode = 0
                $system_Drawing_Point = New-Object System.Drawing.Point
                $System_Drawing_Point.X = 39
                $System_Drawing_Point.Y = 259
                $lbl_MXTech.Location = $system_Drawing_Point
                $lbl_MXTech.Name = "lbl_MXTech"
                $System_Drawing_Size = New-Object System.Drawing.Size
                $System_Drawing_Size.Height = 20
                $System_Drawing_Size.width = 87
                $lbl_MXTech.size = $system_Drawing_Size
                $lbl_MXTech.Tabrndex = 14
                $lbl_MXTech.Text = "MX Technician"
                $Admin_Mx.controls.Add($lbl_MXTech)
                $txt_MXTech.DataBindings.DefaultDataSourceUpdateMode = 0
                $System_Drawing_Point = New-Object System.Drawing.Point
                $System_Drawing_Point.x = 129
                $system_Drawing_Point.Y = 256
                $txt_MXTech.Location = $system_Drawing_Point
                $txt_MXTech.Name = "txt_MXTech"
                $System_Drawing_Size = New-Object System.Drawing.Size
                $System_Drawing_size.Height = 20
                $System_Drawing_size.width = 150
                $txt_MXTech.size = $System_Drawing_size
                $txt_MXTech.Tabrndex = 1
                $txt_MXTech.Text = $Params.USER
                $txt_MXTech.add_Textchanged($handler_txt_MXTech_Textchanged)
                $Admin_MX.Controls.Add($txt_MXTech)
            #endregion
            #region MX Performed
                $lbl_MXLabor.DataBindings.DefaultDataSourceUpdateMode = 0
                $System_Drawing_Point = New-Object System.Drawing.Point
                $System_Drawing_Point.x  = 39
                $system_Drawing_Point.Y = 289
                $lbl_MXLabor.Location = $system_Drawing_Point
                $lbLMXLabor.Name = "lbLMXLabor"
                $System_Drawing_Size = New-Object System.Drawing.Size
                $system_Drawing_size.Height = 21
                $system_Drawing_size.width = 77
                $lbl_MXLabor.Slze = $System_Drawing_Size
                $lbl_MXLabor.Tabrndex = 12
                $lbLMXLabor.Text = "MX Performed"
                $Admin_MX.Controls.Add($lbl_MXLabor)
                $txt_MXLabor.DataBindings.DefaultDataSourceUpdateMode = 0
                $system_Drawing_Point = New-Object System.Drawing.Point
                $system_Drawing_Point.X = 39
                $System_Drawing_Point.Y = 313
                $txt_MXLabor.Location = $System_Drawing_Point
                $txt_MXLabor.Multiline = $True
                $txt_MXLabor.Name = "txt_MXLabor"
                $system_Drawing_size = New-Object System.Drawing.Size
                $System_Drawing_size.Height = 38
                $System_Drawing_size.Width = 139
                $txt_MXLabor.Slze = $System_Drawing_size
                $txt_MXLabor.Tabrndex = 2
                $txt_MXLabor.Text = "Routine Maintenance"
                $txt_MXLabor.add_Textchanged( $handler_txt_MXLabor_Textchanged)
                $Admin_MX.Controls.Add($txt_MXLabor)
            #endregion
            #region Non-Editable Fields
                #region Date
                    $lbl_Date.DataBindings.DefaultDataSourceUpdateMode = 0
                    $System_Drawing_Point = New-Object System.Drawing.Point
                    $system_Drawing_Point.x = 39
                    $system_Drawing_Point.Y = 71
                    $lbl_Date.Location = $System_Drawing_Point
                    $lbLDate.Name = "lbLDate"
                    $system_Drawing_size = New-Object System.Drawing.Size
                    $system_Drawing_size.Height = 21
                    $System_Drawing_size.width = 41
                    $lbl_Date.size = $System_Drawing_Size
                    $lbl_Date.Tabrndex = 1
                    $lbl_Date.Text = "Date"
                    $Admin_MX.Controls.Add($lbl_Date)
                    $txt_Date.DataBindings.DefaultDataSourceUpdateMode = 0
                    $system_Drawing_Point = New-Object System.Drawing.Point
                    $system_Drawing_Point.x = 80
                    $system_Drawing_Point.Y = 68
                    $txt_Date.Location = $System_Drawing_Point
                    $txt_Date.Name = "txt_Date"
                    $System_Drawing_Size = New-Object System.Drawing.Size
                    $system_Drawing_Size.Height = 20
                    $System_Drawing_size.width = 105
                    $txt_Date.size = $System_Drawing_size
                    $txt_Date.Tabstop = $False
                    #$txt_Date.Tabrndex = 6
                    $txt_Date.Text = $Params.Date
                    $txt_Date.Enabled = 0
                    $Admin_Mx.controls.Add($txt_Date)
                #endregion
                #region Time
                    $lbl_Time.DataBindings.DefaultDataSourceUpdateMode = 0
                    $System_Drawing_Point = New-Object System.Drawing.Point
                    $system_Drawing_Point.X = 238
                    $system_Drawing_Point.Y = 71
                    $lbl_Time.Location = $System_Drawing_Point
                    $lbl_Time.Name = "label3"
                    $system_Drawing_Size = New-Object System.Drawing.Size
                    $system_Drawing_size.Height = 23
                    $System_Drawing_size.width = 39
                    $lbl_Time.size = $System_Drawing_size
                    $lbl_Time.Tabrndex = 2
                    $lbl_Time.Text = "Time"
                    $Admin_MX.Controls.Add($lbl_Time)
                    $txt_Time.oataBindings.DefaultDataSourceUpdateMode = 0
                    $system_Drawing_Point = New-Object System.Drawing.Point
                    $system_Drawing_Point.x = 278
                    $system_Drawing_Point.Y = 68
                    $txt_Time.Location = $system_Drawing_Point
                    $txt_Time.Name = "txt_Time"
                    $system_Drawing_size = New-Object System.Drawing.Size
                    $system_Drawing_Size.Height = 20
                    $system_Drawing_size.width = 115
                    $txt_Time.size = $System_Drawing_size
                    $txt_Time.Tabstop = $False
                    #$txt_Time.Tabrndex = 7
                    $txt_Time.Text = $Params.Time
                    $txt_Time.Enabled = 0
                    $Admin_Mx.controls.Add( $txt_Time)
                #endregion
                #region user
                    $lbl_user.DataBindings.DefaultDataSourceUpdateMode = 0
                    $system_Drawing_Point = New-Object System.Drawing.Point
                    $System_Drawing_Point.x = 39
                    $system_Drawing_Point.Y = 117
                    $lbl_user.Location = $System_Drawing_Point
                    $lbl_user.Name = "label4"
                    $System_Drawing_Size = New-Object System.Drawing.Size
                    $system_Drawing_Size.Height = 18
                    $System_Drawing_size.width = 41
                    $lbl_user.size = $system_Drawing_size
                    $lbl_user.Tabrndex = 3
                    $lbl_user.Text = "user"
                    $Admin_MX.Controls.Add($lbl_user)
                    $txt_user.DataBindings.DefaultDataSourceUpdateMode = 0
                    $System_Drawing_Point = New-object System.Drawing.Point
                    $System_Drawing_Point.X = 80
                    $System_Drawing_Point.Y = 113
                    $txt_user.Location = $system_Drawing_Point
                    $txLUser.Name = "txt_user"
                    $system_Drawing_size = New-Object System.Drawing.Size
                    $system_Drawing_size.Height = 20
                    $system_Drawing_size.width = 104
                    $txt_user.s | ze = $system_Drawing_size
                    $txLUser.Tabstop = 0
                    $txt_user.Text = $Params.USER
                    $txt_user.Enabled = 0
                    $Admin_Mx.controls.Add($txt_user)
                #endregion
                #region system
                    $lbl_system.DataBindings.DefaultDataSourceUpdateMode = 0
                    $system_Drawing_Point = New-Object System.Drawing.Point
                    $System_Drawing_Point.x = 233
                    $system_Drawing_Point.Y = 118
                    $lbl_system.Location = $System_Drawing_Point
                    $lbl_system.Name = "labelS"
                    $System_Drawing_Size = New-Object System.Drawing.Size
                    $system_Drawing_Size.Height = 17
                    $System_Drawing_Size.width = 44
                    $lbl_system.size = $system_Drawing_size
                    $lbl_system.Tabrndex = 4
                    $lbl_system.Text = "system"
                    $lbl_system.add_click( $handler_label5_click)
                    $Admin_Mx.controls.Add($lbl_system)
                    $txt_system.DataBindings.DefaultDataSourceUpdateMode = 0
                    $System_Drawing_Point = New-Object System.Drawing.Point
                    $System_Drawing_Point.x = 278
                    $system_Drawing_Point.Y = 115
                    $txt_system.Location = $System_Drawing_Point
                    $txt_system.Name = "txt_system"
                    $System_Drawing_size = New-Object System.Drawing.Size
                    $system_Drawing_Size.Height = 20
                    $System_Drawing_size.width = 115
                    $txt_System.size = $System_Drawing_size
                    $txt_system.Tabstop = 0
                    #$txt_System.Tabrndex = 9
                    $txt_system.Text = $Params.system
                    $txt_system.Enabled = 0
                    $Admin_MX.Controls.Add($txt_System)
                #endregion
                #region Log File
                    $lbl_logFile.DataBindings.DefaultDataSourceUpdateMode = 0
                    $System_Drawing_Point = New-Object System.Drawing.Point
                    $System_Drawing_Point.x = 39
                    $system_Drawing_Point.Y = 149
                    $lbl_logFile.Location = $System_Drawing_Point
                    $lbl_logFile.Name = "label6"
                    $System_Drawing_size = New-Object System.Drawing.Size
                    $system_Drawing_size.Height = 21
                    $System_Drawing_size.width = 50
                    $lbl_logFile.size = $system_Drawing_size
                    $lbl_logFile.Tabrndex = 5
                    $lbl_logFile.Text = "Log File"
                    $Admin_Mx.controls.Add($lbl_logFile)
                    $txt_logFile.DataBindings.DefaultDataSourceUpdateMode = 0
                    $System_Drawing_Point = New-Object System.Drawing.Point
                    $system_Drawing_Point.x = 39
                    $System_Drawing_Point.Y = 166
                    $txt_logFile.Location = $System_Drawing_Point
                    $txt_logFile.Name = "txt_logFile"
                    $system_Drawing_Size = New-Object System.Drawing.Size
                    $System_Drawing_size.Height = 20
                    $System_Drawing_size.width = 357
                    $txt_logFile.Slze = $System_Drawing_size
                    $txt_logFile.Tabstop = $False
                    #$txt_logFile.Tabrndex = 10
                    $txt_logFile.Text = $Params.LogFile
                    $txt_logFile.Enabled = 0
                    $Admin_MX.Controls.Add($txt_logFile)
                #endregion
            #endregion
            #region IN-WORK
                <#
                    $listBox1.DataBindings.DefaultDataSourceUpdateMode = 0
                    $listBox1.FormattingEnabled = $True
                    $system_Drawing_Point = New-object system.Drawing.Point
                    $system_Drawing_Point.X = 344
                    $System_Drawing_Point.Y = 201
                    $listBox1.Location = $system_Drawing_Point
                    $1 | stBoxl. Name = "l | stBox1"
                    $system_Drawing_size = New-object system.Drawing.Size
                    $System_Drawing_Size.Height = 17
                    $System_Drawing_size.width = 91
                    $listBox1.size = $System_Drawing_size
                    $listBox1.Tabrndex = 23
                    $Admin_MX.Controls.Add($listsoxl)
                    $comboBoxl.DataBindings.DefaultDataSourceUpdateMode = 0
                    $comboBoxl.FormattingEnabled = $True
                    $System_Drawing_Point = New-object system.Drawing.Point
                    $System_Drawing_Point.X = 3
                    $System_Drawing_Point.v = 200
                    $comboBoxl.Location = $system_Drawing_Point
                    $comboBoxl.Name = "comboBoxl"
                    $system_Drawing_size = New-object system.Drawing.size
                    $System_Drawing_Size.Height = 21
                    $System_Drawing_size.width = 71
                    $combosoxl.size = $system_Drawing_size
                    $comboBoxl.Tabindex = 22
                    $Admin_MX.Controls.Add($comboBoxl)
                #>
            #endregion
            #save the initial state of the form
            $InitialFormwindowstate = $Admin_MX.Windowstate
            #Init the onLoad event to correct the initial state of the form
            $Admin_MX.add_Load($OnLoadForm_Statecorrection)
            #Show the Form
            $null = $Admin_MX.Showoialog()

            If ($Params.'MX Performed'-eq $null ){ $Params.' MX Performed' = $txt_MXLabor.Text }
            If ($Params.'MX Description'-eq $null ){ $Params.'MX Description' = $txt_MXDesc.Text }
            If ($Params.'MX Technician'-eq $null ){ $Params.'MX Technician' = $txt_MXTech.Text }
            If ($Params.Escort -eq $null ){ $Params.Escort = $txt_Escort.Text }
            If ($Params.Equipment -eq $null ){ $Params.Equipment = $txt_Equip.Text }
        }
    # open the Form
        AdminForm
    # Save to log File
        $Params | Export-csv -NoTypeinformation -Path $Params.LogFile -Append
        # Test-Path -PathType Leaf $Params.LogFile
#endregion
