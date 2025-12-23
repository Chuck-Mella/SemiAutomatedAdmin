<#
.SYNOPSIS
    Sample form definition for demo1.ps1 script

.DESCRIPTION
    This file contains form definition properties and events are loaded with new-form function in module FormsBuild

.NOTES
    Author  : Claude Débieux - claude@get-code.ch
    More information and working demo on GitHub

.LINK
    https://get-code.ch
    https://github.com/get-code-ch/FormsBuilder
#>

@{
    # DialogForm Definition
    Form     = @{
        # Form properties
        Properties = @{
            Name            = 'Demo1Form'
            Text            = 'Demo1 Form'
            Width           = 400
            Height          = 400
            Anchor          = 'Left,Top'
            AutoSize        = $False
            MaximizeBox     = $False
            MinimizeBox     = $False
            ControlBox      = $True # $True or $False to show close icon on top right corner
            FormBorderStyle = 'FixedSingle' # Fixed3D, FixedDialog, FixedSingle, Sizable, None, FixedToolWindow, SizableToolWindow
        }
        # Form Events (function must defined in calling script)
        Events     = @{
            Load = 'Form_Load'    
        }
    }

    # Controls Definition
    Controls = @(
        @{
            Control    = "Label"
            Properties = @{
                Text  = 'Text'
                Name  = 'Label1'
                Top   = 7
                Left  = 5
                Width = 60
                Font = 'Arial, 11, style=Bold,Italic'
                ForeColor = 'Red'
            }
        },
        @{
            Control    = "TextBox"
            Properties = @{
                Name  = 'TextBox1'
                Top   = 7
                Left  = 70
                Width = 210
            }
            # Hanling event when text is changed
            Events     = @{
                TextChanged = 'TextBox1_OnChange'    
            }
        },
        @{
            Control    = "Label"
            Properties = @{
                Text  = 'TextBox1'
                Name  = 'Label2'
                Top   = 40
                Left  = 5
                Width = 60
            }
        },
        @{
            Control    = "Label"
            Properties = @{
                Text  = '<Text>'
                Name  = 'Label3'
                Top   = 40
                Left  = 70
                Width = 210
            }
        },
        @{
            Control    = "DataGridView"
            Properties = @{
                Name                 = 'DataGridView1'
                Top                  = 70
                Left                 = 5
                Height               = 200
                Width                = 375
                ColumnHeadersVisible = $True
                RowHeadersVisible    = $false
                SelectionMode        = 'FullRowSelect'
                MultiSelect          = $false
                ReadOnly             = $True
                
            }
            Events     = @{
                CellClick = 'DataGridView1_CellClick'
                CellDoubleClick = 'DataGridView1_CellDoubleClick'
            }
        },
        @{
            Control             = "DateTimePicker"
            Properties          = @{
                Name            = 'DateTiemPicker1'
                Top             = 280
                Left            = 5
                Width           = 170
            }
            Events     = @{
                ValueChanged     = 'DateTimePicker1_ValueChanged'
            }
        },
        @{
            Control             = "Label"
            Properties          = @{
                Name            = 'LabelDate1'
                Top             = 280
                Left            = 185
                Width           = 120
            }
        },
        # Form Quit Button
        @{
            Control    = "Button"
            Properties = @{
                Text  = 'Quit'
                Name  = 'QuitBtn'
                Top   = 315
                Left  = 170
                Width = 60
                Height = 25
            }
            Events     = @{
                Click = 'QuitBtn_Click'    
            }
        } 
    )
}
