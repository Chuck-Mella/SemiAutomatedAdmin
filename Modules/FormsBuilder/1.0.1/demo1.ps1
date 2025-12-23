<#
.SYNOPSIS
    Powershell script for demonstration of usage of FormsBuilder module

.DESCRIPTION
    This script demonstrate usage if FormsBuilder module

.NOTES
    Author  : Claude Débieux - claude@get-code.ch
    More information and working demo on GitHub

.LINK
    https://get-code.ch
    https://github.com/get-code-ch/FormsBuilder
#>


### Following functions handling event on $MainForm.Form ###
# This function is called when forms is loaded (after $MainForm.Form.ShowDialog())
Function Form_Load() {
    # Set source of DataGridView
    # This object can also accessed directly from the form
    # $MainForm.Form.Controls["DataGridView1"].DataSource is synonym 
    # to $MainForm.Controls.DataGridView1.DataSource
    $MainForm.Controls.DataGridView1.DataSource = $demoArray

    # Change de fore coler of Label3
    $MainForm.Controls.Label3.ForeColor = 'Blue'
}

# DataGridView1 event handling
Function DataGridView1_CellClick() {
    # For the demo, when we make a simple click on one row of DataGridView1 we clear content of TextBox1
    $MainForm.Controls.TextBox1.Text = ''
}
Function DataGridView1_CellDoubleClick() {
    # For the demo, when we make a double click on one row of DataGridView1 we set the content of TextBox1 with name cell of the rows
        $MainForm.Controls.TextBox1.Text = $this.CurrentRow.Cells["Name"].Value
}

# Textbox change event handling
Function TextBox1_OnChange(){
    if (!$this.Text -eq '') {
        $MainForm.Controls.Label3.Text = $this.Text
    } else {
        $MainForm.Controls.Label3.Text = '<Text>'
    }
}

function DateTimePicker1_ValueChanged () {
    $MainForm.Controls.LabelDate1.Text = $this.Value.ToString("dd-MMM-yyyy")
}

Function QuitBtn_Click() {
    # When Quit button is click we close the form
    $MainForm.Form.Close()
}

### Begin of script ###
Import-Module ".\FormsBuilder" -Force

Clear-Host
$FormsFile = ".\demo1Form.psd1"

# For the demo we load an array with list of psdrive
$demoArray = New-Object System.Collections.ArrayList 
$demoArray.AddRange((get-psdrive | Select-Object Name, Provider, root)) | Out-Null

$MainForm = New-Form($FormsFile)
$MainForm.Form.ShowDialog()
