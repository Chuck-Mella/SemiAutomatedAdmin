        #region Form Building

            $window = New-Object Windows.Window
            $eventHandler = [Windows.Input.MouseButtonEventHandler]{$this.Close()}
            $window.Add_MouseDown($eventHandler)
            $window.Content = "Click Me and I will Go Away"
            $window.SizeToContent = "WidthAndHeight"
            $null = $window.ShowDialog()

            # However, honestly, clicking just one button isn't that useful.  Instead, let's build something that will help us find commands.  The next example will help you find a command.

            $window = New-Object Windows.Window
            $window.SizeToContent = "WidthAndHeight"
            $label = New-Object Windows.Controls.Label
            $label.Content = "Type A command (And watch the list change)"
            $textBox = New-Object Windows.Controls.TextBox
            $listBox = New-Object Windows.Controls.Listbox
            $listBox.Width = 300
            $listBox.Height = 200
            # When the text changes, use Get-Command to display a shortened list of commands
            $textBox.add_TextChanged({
                $listBox.ItemsSource = @(Get-Command "*$($textbox.Text)*" | ForEach-Object { $_.Name })
            })
            # When the listbox's selection changes, set the text to the selection
            $listBox.add_SelectionChanged({
                $textBox.Text = $listBox.SelectedItem
            })
            $button = New-Object Windows.Controls.Button
            $button.Content = "Select Command"
            $button.add_Click({$window.Close()})
            $stackPanel = New-Object Windows.Controls.StackPanel
            $stackPanel.Orientation="Vertical"
            $children = $label, $textBox, $listbox, $button
            foreach ($child in $children) { $null = $stackPanel.Children.Add($child) }
            $window.Content = $stackPanel
            $null = $window.ShowDialog()
            $textbox.Text

            # In the next example, we'll show how to use Drag and Drop to populate a listbox.

            $window = New-Object Windows.Window
            $window.SizeToContent = "WidthAndHeight"
            $label = New-Object Windows.Controls.Label
            $window.Title = $label.Content = "Drag Scipts Here, DoubleClick to Run"
            $listBox = New-Object Windows.Controls.Listbox
            $listBox.Height = 200
            $listBox.AllowDrop = $true
            $listBox.add_MouseDoubleClick({Invoke-Expression "$($listbox.SelectedItem)" -ea SilentlyContinue })  
            $displayedFiles = @()
            $listBox.add_Drop({
                $files = $_.Data.GetFileDropList()
                foreach ($file in $files) {
                   if ($file -is [IO.FileInfo]) {
                      $displayedFiles = $file
                   } else {
                      $displayedFiles += Get-ChildItem $file -recurse | Where-Object { $_ -is [IO.FileInfo]} | ForEach-Object { $_.FullName }
                   }
                }
                $listBox.ItemsSource = $displayedFiles | Sort-Object
            })
            $runButton = New-Object Windows.Controls.Button
            $runButton.Content = "Run"
            $runButton.add_Click({Invoke-Expression "$($listbox.SelectedItem)" -ea SilentlyContinue })
            $clearButton = New-Object Windows.Controls.Button
            $clearButton.Content = "Clear"
            $clearButton.add_Click({$listBox.ItemsSource = @()})
            $stackPanel = New-Object Windows.Controls.StackPanel
            $stackPanel.Orientation="Vertical"
            $children = $label, $listbox, $runButton, $clearButton
            foreach ($child in $children) { $null = $stackPanel.Children.Add($child) }
            $window.Content = $stackPanel
            $null = $window.ShowDialog()

 

            $circleSize = Get-Random -min 200 -max 450
            $color = "Red", "Green","Blue","Orange","Yellow" | Get-Random
            "<Ellipse xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'
              Width='$circleSize'
              Height='$circleSize'
              Fill='$color' />" |  Show-Control
        #endregion
        #region Form Building {XAML]
        @"
        <Label xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' FontSize='24'>Hello World</Label>
"@ | Show-Control

        # InkCanvas (was 7 lines, now 1 line):

        "<InkCanvas xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' />" | Show-Control

        # Random Circle (was 9 lines, now 6 lines)

        $circleSize = Get-Random -min 200 -max 450
        $color = "Red", "Green","Blue","Orange","Yellow" | Get-Random
        "<Ellipse xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'
          Width='$circleSize'
          Height='$circleSize'
          Fill='$color' />" |  Show-Control

        # Slider (was 8 lines, now 1 line)

        "<Slider xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' Minimum='1′ Maximum='10'/>"| Show-Control

        # Label & Textbox (was 11 lines, now 6 lines)

        @"
        <StackPanel xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'>
        <Label FontSize='20'>Type Something</Label>
        <TextBox />
        </StackPanel>
"@ |  Show-Control

        # Click & Close (was 6 lines, now 3 lines)

        @"
        <Button FontSize='20' xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'>Click Me</Button>
"@ | Show-Control @{"Click" = {$window.close()}}

        # Select-Command (was 26 lines, now 19)

        @"
        <StackPanel xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'>
        <Label FontSize='14'>Type a Command</Label>
        <TextBox Name="CommandTextBox"/>
        <ListBox Name="CommandListBox" Width='200′ Height='200'/>
        <Button Name="SelectCommandButton" FontSize='14'>Select Command</Button>
        </StackPanel>
"@ | Show-Control @{
           "CommandTextBox.TextChanged" = {      
               $listBox = $window.Content.FindName("CommandListBox")
               $textBox = $window.Content.FindName("CommandTextBox")
               $listBox.ItemsSource = @(Get-Command "*$($textbox.Text)*" | ForEach-Object { $_.Name })
           }
           "CommandListBox.SelectionChanged" = {
               $textBox = $window.Content.FindName("CommandTextBox")
               $textBox.Text = $this.SelectedItem
           }
           "SelectCommandButton.Click" = {$window.Close()}
        }

        # Drag & Drop (was 33 lines, now 31)

        @"
        <StackPanel xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'>
        <Label FontSize='14'>Drag Scripts Here, DoubleClick to Run</Label>
        <ListBox Name="CommandListBox" AllowDrop='True' Height='200'/>
        <Button Name="RunCommandButton" FontSize='14'>Run File</Button>
        <Button Name="ClearCommandButton" FontSize='14'>Clear List</Button>
        </StackPanel>
"@ | Show-Control
         @{
           "CommandListBox.MouseDoubleClick" = {
               Invoke-Expression "$($this.SelectedItem)" -ea SilentlyContinue
           }
           "CommandListBox.Drop" = {
               $files = $_.Data.GetFileDropList()
               foreach ($file in $files) {
                   if ($file -is [IO.FileInfo]) {
                       $displayedFiles = $file
                   } else {
                       $displayedFiles += Get-ChildItem $file -recurse | Where-Object { $_ -is [IO.FileInfo]} | ForEach-Object { $_.FullName }
                   }          
               }
               $listBox.ItemsSource = $displayedFiles | Sort-Object  
           }
           "RunCommandButton.Click" = {
               $listBox = $window.Content.FindName("CommandListBox")
               Invoke-Expression "$($listbox.SelectedItem)" -ea SilentlyContinue
           }
           "ClearCommandButton.Click" = {
               $window.Content.FindName("CommandListBox").ItemsSource=@()
           }
        }

        #>
        function Show-Control
        {
            <#
                Displays one or more controls.
                Controls are piped to Show-Control as XAML or as a .NET object.
                Events are passed as a dictionary of name/scriptblocks
                Event Hashtable keys can be like
                    EVENTNAME (event on the object piped to Show-Control)
                    TARGET.EVENTNAME (event on the named object within the control)
                    WINDOW.EVENTNAME (event on the window)
            #>
            [CmdletBinding(DefaultParameterSetName='VisualElement')]
            param
            (
                [Parameter(
                    Mandatory=$true,
                    ParameterSetName="VisualElement",
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true
                    )] [Windows.Media.Visual]$control,    
                [Parameter(
                    Mandatory=$true,
                    ParameterSetName="Xaml",
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true)]    
                    [string]$xaml,    
                [Parameter(
                   ValueFromPipelineByPropertyName=$true,Position=0)]    
                   [Hashtable]$event,
               [Hashtable]$windowProperties
            )

            Begin
            {
                $window = New-Object Windows.Window
                $window.SizeToContent = "WidthAndHeight"
                if ($windowProperties)
                {
                    foreach ($kv in $windowProperties.GetEnumerator()) { $window."$($kv.Key)" = $kv.Value }
                }
                $visibleElements = @()
                $windowEvents = @()
            }

            Process
            {      
               switch ($psCmdlet.ParameterSetName)
               {
                   "Xaml"
                   {
                       $c_Xaml = [string]$xaml -replace "'",'"'
                       $f = [System.xml.xmlreader]::Create([System.IO.StringReader] $c_xaml)
                       $visibleElements += ([system.windows.markup.xamlreader]::load($f))      
                   }
                   "VisualElement"
                   {
                       $visibleElements+=$control
                   }
               }
               if ($event)
               {
                    $element = $visibleElements[-1]      
                    foreach ($evt in $event.GetEnumerator())
                    {
                        # If the event name is like *.*, it is an event on a named target, otherwise, it's on any of the events on the top level object
                        if ($evt.Key.Contains("."))
                        {
                            $targetName = $evt.Key.Split(".")[1].Trim()
                            if ($evt.Key -like "Window.*") { $target = $window }
                            else { $target = ($visibleElements[-1]).FindName(($evt.Key.Split(".")[0])) }                      
                        }
                        else
                        {
                            $target = $visibleElements[-1]
                            $targetName = $evt.Key
                        }
                        $target | Get-Member -type Event |
                            Where-Object { $_.Name -eq $targetName } |
                            ForEach-Object {
                            $eventMethod = $target."add_$targetName"
                            $eventMethod.Invoke($evt.Value)
                            }              
                   }
               }
            }

            End
            {
                if ($visibleElements.Count -gt 1)
                {
                    $wrapPanel = New-Object Windows.Controls.WrapPanel
                    $visibleElements | ForEach-Object { $null = $wrapPanel.Children.Add($_) }
                    $window.Content = $wrapPanel
                }
                else
                {
                    if ($visibleElements) { $window.Content = $visibleElements[0] }
                }
                $null = $window.ShowDialog()
            }
        }
        #endregion
        #region Form Building [XAML 3]
        #-------------------------------------------------------------#
        #----Initial Declarations-------------------------------------#
        #-------------------------------------------------------------#

        Add-Type -AssemblyName PresentationCore, PresentationFramework
        $Xaml = (Dec64 'DQogICAgPFdpbmRvdyB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwvcHJlc2VudGF0aW9uIiBXaWR0aD0iOTM5IiBIZWlnaHQ9IjcxMyIgSG9yaXpvbnRhbEFsaWdubWVudD0iTGVmdCIgVmVydGljYWxBbGlnbm1lbnQ9IlRvcCIgTWFyZ2luPSIwLDAsMCwwIj4NCiAgICAgICAgPEdyaWQgTWFyZ2luPSIyODYsMjMxLC02NiwxNyI+DQogICAgICAgICAgICA8VGV4dEJveCBIb3Jpem9udGFsQWxpZ25tZW50PSJMZWZ0IiBWZXJ0aWNhbEFsaWdubWVudD0iVG9wIiBIZWlnaHQ9IjQyMSIgV2lkdGg9Ijg3NSIgVGV4dFdyYXBwaW5nPSJXcmFwIiBNYXJnaW49IjM1LDIyOSwwLDAiIE5hbWU9IkNvZGUiLz4NCiAgICAgICAgICAgIDxUZXh0Qm94IEhvcml6b250YWxBbGlnbm1lbnQ9IkxlZnQiIFZlcnRpY2FsQWxpZ25tZW50PSJUb3AiIEhlaWdodD0iMjkiIFdpZHRoPSIzNzkiIFRleHRXcmFwcGluZz0iV3JhcCIgTWFyZ2luPSIzNSwxOCwwLDAiLz4NCiAgICAgICAgICAgIDxUZXh0Qm94IEhvcml6b250YWxBbGlnbm1lbnQ9IkxlZnQiIFZlcnRpY2FsQWxpZ25tZW50PSJUb3AiIEhlaWdodD0iMjMiIFdpZHRoPSIxMjAiIFRleHRXcmFwcGluZz0iV3JhcCIgTWFyZ2luPSI0MzIuODQzNzUsMTUuOTg0Mzc1LDAsMCIvPg0KICAgICAgICAgICAgPFRleHRCb3ggSG9yaXpvbnRhbEFsaWdubWVudD0iTGVmdCIgVmVydGljYWxBbGlnbm1lbnQ9IlRvcCIgSGVpZ2h0PSIyMyIgV2lkdGg9IjEyMCIgVGV4dFdyYXBwaW5nPSJXcmFwIiBNYXJnaW49IjU3NSwxNiwwLDAiLz4NCiAgICAgICAgICAgIDxUZXh0Qm94IEhvcml6b250YWxBbGlnbm1lbnQ9IkxlZnQiIFZlcnRpY2FsQWxpZ25tZW50PSJUb3AiIEhlaWdodD0iMjQiIFdpZHRoPSIxMzkiIFRleHRXcmFwcGluZz0iV3JhcCIgTWFyZ2luPSIzNi44NDM3NSw2OS45ODQzNzUsMCwwIi8+DQogICAgICAgICAgICA8VGV4dEJveCBIb3Jpem9udGFsQWxpZ25tZW50PSJMZWZ0IiBWZXJ0aWNhbEFsaWdubWVudD0iVG9wIiBIZWlnaHQ9IjMzIiBXaWR0aD0iMjUxIiBUZXh0V3JhcHBpbmc9IldyYXAiIE1hcmdpbj0iMTkwLDY1Ljk4NDM3NSwwLDAiLz4NCiAgICAgICAgICAgIDxUZXh0Qm94IEhvcml6b250YWxBbGlnbm1lbnQ9IkxlZnQiIFZlcnRpY2FsQWxpZ25tZW50PSJUb3AiIEhlaWdodD0iMzIiIFdpZHRoPSIzMTgiIFRleHRXcmFwcGluZz0iV3JhcCIgTWFyZ2luPSI0NjcuODQzNzUsNjUuOTg0Mzc1LDAsMCIvPg0KICAgICAgICAgICAgPFRleHRCb3ggSG9yaXpvbnRhbEFsaWdubWVudD0iTGVmdCIgVmVydGljYWxBbGlnbm1lbnQ9IlRvcCIgSGVpZ2h0PSIyMyIgV2lkdGg9IjEyMCIgVGV4dFdyYXBwaW5nPSJXcmFwIiBNYXJnaW49IjM3Ljg0Mzc1LDEyNS45ODQzNzUsMCwwIi8+DQogICAgICAgICAgICA8Q2hlY2tCb3ggSG9yaXpvbnRhbEFsaWdubWVudD0iTGVmdCIgVmVydGljYWxBbGlnbm1lbnQ9IlRvcCIgQ29udGVudD0iQ2hlY2tCb3giIE1hcmdpbj0iMjE3Ljg0Mzc1LDEyMy45ODQzNzUsMCwwIi8+DQogICAgICAgICAgICA8Q2hlY2tCb3ggSG9yaXpvbnRhbEFsaWdubWVudD0iTGVmdCIgVmVydGljYWxBbGlnbm1lbnQ9IlRvcCIgQ29udGVudD0iQ2hlY2tCb3giIE1hcmdpbj0iMzIxLjg0Mzc1LDEyNC45ODQzNzUsMCwwIi8+DQogICAgICAgICAgICA8VGV4dEJveCBIb3Jpem9udGFsQWxpZ25tZW50PSJMZWZ0IiBWZXJ0aWNhbEFsaWdubWVudD0iVG9wIiBIZWlnaHQ9IjIzIiBXaWR0aD0iMTIwIiBUZXh0V3JhcHBpbmc9IldyYXAiIE1hcmdpbj0iMzkuODQzNzUsMTc5Ljk4NDM3NSwwLDAiLz4NCg0KICAgICAgICAgICAgPENoZWNrQm94IEhvcml6b250YWxBbGlnbm1lbnQ9IkxlZnQiIFZlcnRpY2FsQWxpZ25tZW50PSJUb3AiIENvbnRlbnQ9IkNoZWNrQm94IiBNYXJnaW49IjIxNS44NDM3NSwxNzQuOTg0Mzc1LDAsMCIvPg0KICAgICAgICAgICAgPFRleHRCb3ggSG9yaXpvbnRhbEFsaWdubWVudD0iTGVmdCIgVmVydGljYWxBbGlnbm1lbnQ9IlRvcCIgSGVpZ2h0PSIyMyIgV2lkdGg9IjEyMCIgVGV4dFdyYXBwaW5nPSJXcmFwIiBNYXJnaW49Ijc4MSwxNzgsMCwwIi8+DQogICAgICAgICAgICA8QnV0dG9uIENvbnRlbnQ9IkJ1dHRvbiIgSG9yaXpvbnRhbEFsaWdubWVudD0iTGVmdCIgVmVydGljYWxBbGlnbm1lbnQ9IlRvcCIgV2lkdGg9Ijc1IiBNYXJnaW49Ijg0MywyMCwwLDAiLz4NCiAgICAgICAgICAgIDxCdXR0b24gQ29udGVudD0iQnV0dG9uIiBIb3Jpem9udGFsQWxpZ25tZW50PSJMZWZ0IiBWZXJ0aWNhbEFsaWdubWVudD0iVG9wIiBXaWR0aD0iNzUiIE1hcmdpbj0iODQ0LDUyLDAsMCIvPg0KICAgICAgICAgICAgPEJ1dHRvbiBDb250ZW50PSJCdXR0b24iIEhvcml6b250YWxBbGlnbm1lbnQ9IkxlZnQiIFZlcnRpY2FsQWxpZ25tZW50PSJUb3AiIFdpZHRoPSI3NSIgTWFyZ2luPSIzOTMsMTg5LDAsMCIvPg0KICAgICAgICAgICAgPFRleHRCb3ggSG9yaXpvbnRhbEFsaWdubWVudD0iTGVmdCIgVmVydGljYWxBbGlnbm1lbnQ9IlRvcCIgSGVpZ2h0PSIyMyIgV2lkdGg9IjEyMCIgVGV4dFdyYXBwaW5nPSJXcmFwIiBNYXJnaW49IjQ2Ni44NDM3NSwxODAuOTg0Mzc1LDAsMCIvPg0KICAgICAgICA8L0dyaWQ+DQoNCg0KICAgIDwvV2luZG93Pg0K')


        #-------------------------------------------------------------#
        #----Control Event Handlers-----------------------------------#
        #-------------------------------------------------------------#


        #region Logic
        #Write your code here
        #endregion


        #-------------------------------------------------------------#
        #----Script Execution-----------------------------------------#
        #-------------------------------------------------------------#

        $Window = [Windows.Markup.XamlReader]::Parse($Xaml)

        [xml]$xml = $Xaml

        $xml.SelectNodes("//*[@Name]") | ForEach-Object { Set-Variable -Name $_.Name -Value $Window.FindName($_.Name) }

        $Window.ShowDialog()
        #endregion

