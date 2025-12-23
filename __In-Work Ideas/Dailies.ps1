$edge = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
$chrome = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Google Chrome.lnk"
$ffox = "C:\Program Files\Mozilla Firefox\firefox.exe"

# Open Outlook
    & "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Outlook.lnk"
    Sleep -Milliseconds 300

# Open Amentum Email
    & $edge https://login.microsoftonline.com
    Sleep -Milliseconds 300

# Open Amentum WorkDay
    & $edge 'https://www.myworkday.com/pae'
    Sleep -Milliseconds 300

# Open DEPOT (Weekly)
    If ((get-date).DayOfWeek -eq 'Wednesday')
    {
        & $chrome 'https://depo.apps.deas.mil/DepoV2/Banner'
        Sleep -Milliseconds 300
    }

