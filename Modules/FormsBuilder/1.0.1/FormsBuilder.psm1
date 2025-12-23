<#
.SYNOPSIS
    PowerShell Module to build a windows.forms object from a defintion file

.DESCRIPTION
    FormsBuilder is a PowerShell module to load a Windows.Forms from a PSD1 definition file, all Windows.Forms controls can be defined.
    PSD1 file must have following structure

    @{
        Form = @{
            # Madatory
            Properties =  @{
                Name    = 'Form Name'
                ... Form property fields ...

            }
            # Optional
            Events  = @{
                Load = 'Form_Load'
                ... Form events ...
                Event function must be defined in calling script
            }
        }
        Controls = @(
            @{
                Control     = "Label", "TextBox", "Button".....
                Properties  = @{
                    Name    = 'ControlName'
                    ... Control property fields ....
                }
                # Optional
                Events      = @{
                    TextChanged = 'TextBox_Changed'
                    .....
                }
            },
            ..... Many controls as you want
        )
    }

    The New-Form function
    - Load contents of psd1 file in parameters
    - Create the form
    - Create controls in the form
    - Return an object containing the form and contorls

    # To build the forms
    $MyForm = New-Form('C:\Script\MyForm.psd1') 
    $MyForm.Form.ShowDialog()  # Display the forms

    # Control are defined in Controls property
    $MyForm.Controls.ControlName

.PARAMETER FormsFile
    psd1 files containing the form defintition

.EXAMPLE
    Build a new form with some controls

    $MyForm = New-Form('C:\Script\MyForm.psd1') 
    $MyForm.Form.ShowDialog()  # Display the forms

.NOTES
    Author  : Claude Débieux - claude@get-code.ch

.LINK
    https://get-code.ch
    https://get-code.ch/blog/category/formsbuilder
#>

# Add .Net type to the session
Add-Type -AssemblyName System.Windows.Forms 
Add-Type -AssemblyName System.Drawing 

function New-Form () {
    [CmdletBinding()]
    param(
        [OutputType("System.Collections.Hashtable")]
        [Parameter(Mandatory = $True, 
            ValueFromPipeline = $False,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'File contenaining form definition')]
        [string]$FormsFile
    )

    # Get forms definition from file
    Import-LocalizedData -BaseDirectory (Split-Path $FormsFile) -FileName (Split-Path $FormsFile -Leaf) -BindingVariable 'FormDef'

    # Objects to return (the form and controls)
    $WinForm = New-Object System.Windows.Forms.Form 
    $WinControls = @()

    ### Loading the form defintion ###
    # Loading form properties
    foreach ($k in $FormDef.Form.Properties.Keys) {
        # If defined properties not exist in the form object write an error and exit the script
        if ($WinForm.PSobject.Properties.Name -match $k) {
            $WinForm.$k = $FormDef.Form.Properties.$k
        } else {
            Write-Error -Message "Error: Property $k not exist in windows.form.forms control"
            exit
        }
    }

    # Loading form events
    foreach ($k in $FormDef.Form.Events.Keys) {
        $evt = "Add_$($k)"
        # If defined event not exist in the form object write an error and exit the script
        if ($WinForm.PSobject.Methods.Name -match $evt) {
            $fct = [Scriptblock]::Create($($FormDef.Form.Events.$k))
            $WinForm.$evt($fct) 
        } else {
            Write-Error -Message "Error: Event $k not exist for windows.form.forms control"
            exit
        }
    }
    # TODO Check if every mandatory properties are defined

    ### Loading controls defintion ###
    foreach ($control in $FormDef.Controls) {
        $evt = $null
        $fct = $null

        # Create the new control and check if control is valid
        $c = New-Object System.Windows.Forms.$($control.Control) -ErrorAction SilentlyContinue -ErrorVariable NewObjectError 
        if ($NewObjectError) {
            Write-Error -Message "Error: $($control.Control) invalid for windows.forms"
            exit
        }

        # Loading control properties
        foreach ($k in $control.Properties.Keys) {
            # if control properties not exist write an error and exit the script
            if ( $c.psobject.properties.name -match $k) {
                $c.$k = $control.Properties.$k
            } else {
                Write-Error -Message "Error: $($control.Properties.Name) Property $k not exist for $c control"
                exit
            }
        }

        # Loading control events
        foreach ($k in $control.Events.Keys) {
            $evt = "Add_$($k)"
            $fct = [Scriptblock]::Create($($control.Events.$k))
            # if control evnet not exist write an error and exit the script
            if ($c.PSObject.Methods.Name -match $evt) {
                $fct = [Scriptblock]::Create($($control.Events.$k))
                $c.$evt($fct) 
            } else {
                Write-Error -Message "Error: $($control.Properties.Name) Event $k not exist for $c control"
                exit
            }
        }

        # TODO check if all mandatory properties are defined

        # Add control in the form and in controls return object
        $WinForm.Controls.Add($c)
        $WinControls += @{$c.Name = $c}
    }

    # Return Form object creation
    $FormObject = @()
    $FormObject += @{ Form =  $WinForm }
    $FormObject += @{ Controls = $WinControls }
    
    return $FormObject
}

Export-ModuleMember -Function *