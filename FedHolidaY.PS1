    #region - Federal Holiday
        # Powershell Holiday Checks
        function IsHoliday([datetime] $DateToCheck = (Get-Date))
        {
            [int]$year = $DateToCheck.Year
            $cycle = If (($year % 2) -eq 0){If (($year % 4) -eq 0){' (Federal)'} Else {' (Local)'}} Else {'N/A'}
            If ($DateToCheck.Day -eq 31 -and $DateToCheck.Month -eq 12 -and $DateToCheck.DayOfWeek -eq 'Friday'){$year = $year + 1}
            $HolidaysInYear = @(
                [datetime]"1/1/$year", #New Year's Day on Saturday will be observed on 12/31 of prior year
                $((0..29 | %{([datetime]"1/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Monday'})[2]), # Martin Luther King Day - 3rd Monday in Jan
                $((0..29 | %{([datetime]"2/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Monday'})[2]), #Presidents Day - 3rd Monday in Feb
                (23..30 | %{([datetime]"5/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Monday'})[-1], #Memorial Day
                $(If($year -ge 2021){[datetime]"6/19/$year"}Else{[datetime]"1/1/$year"}), #Juneteenth is a federal holiday since 2021
                [datetime]"7/4/$year",#Independence Day
                (0..6 | %{([datetime]"9/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Monday'})[0], #Labor Day - first Mon in Sept.
                $((0..29 | %{([datetime]"10/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Monday'})[1]), #Columbus Day - 2nd Monday in Oct
                #$(If ($cycle -ne 'N/A'){$((0..7 | %{([datetime]"11/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Tuesday'})[0])}), #Election Day
                $([datetime]"11/11/$year"), #Veterans Day - Nov 11th
                (0..29 | %{([datetime]"11/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Thursday'})[3], #Thanksgiving - last Thu in Nov.
                #$(((0..29 | %{([datetime]"11/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Thursday'})[3]).AddDays(1)), #Black Friday - Day after Thanksgiving
                #$([datetime]"12/24/$year"), #Christmas Eve - Dec 24th
                [datetime]"12/25/$year"#, #Christmas - Dec 25th
                #[datetime]"12/31/$year" #New Years Eve - Dec 31st
                ) | %{$_[0].AddDays($(If($_[0].DayOfWeek -eq 'Saturday'){-1}) + $(If($_[0].DayOfWeek -eq 'Sunday'){+1})) }
            Return $HolidaysInYear.Contains($DateToCheck.Date)
        }
        function Get-FedHolidays([datetime] $DateToCheck = (Get-Date),[switch]$test)
        {
            [int]$year = $DateToCheck.Year
            $cycle = If (($year % 2) -eq 0){If (($year % 4) -eq 0){' (Federal)'} Else {' (Local)'}} Else {'N/A'}
            If ($DateToCheck.Day -eq 31 -and $DateToCheck.Month -eq 12 -and $DateToCheck.DayOfWeek -eq 'Friday'){$year = $year + 1}
            $HolidaysInYear = "
                $(Get-Date "1/1/$year" -f MM/dd/yyyy),,Y,New Year's Day,If on Saturday will be observed on 12/31 of prior year
                $(Get-Date ((0..29 | %{([datetime]"1/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Monday'})[2]) -f MM/dd/yyyy),,Y,Martin Luther King Day,3rd Monday in Jan
                $(Get-Date ((0..29 | %{([datetime]"2/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Monday'})[2]) -f MM/dd/yyyy),,Y,Presidents Day,3rd Monday in Feb
                $(Get-Date ((23..30 | %{([datetime]"5/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Monday'})[-1]) -f MM/dd/yyyy),,Y,Memorial Day,Last Monday in May
                $(If($year -ge 2021){Get-Date ([datetime]"6/19/$year") -f MM/dd/yyyy }Else{Get-Date ([datetime]"1/1/$year")-f MM/dd/yyyy}),,Y,Juneteenth,Federal holiday since 2021
                $(Get-Date ([datetime]"7/4/$year") -f MM/dd/yyyy),,Y,Independence Day,4th July 1776
                $(Get-Date ((0..6 | %{([datetime]"9/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Monday'})[0]) -f MM/dd/yyyy),,Y,Labor Day,first Monday in Sept.
                $(Get-Date ((0..29 | %{([datetime]"10/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Monday'})[1]) -f MM/dd/yyyy),,Y,Columbus Day,2nd Monday in Oct
                $(If ($cycle -ne 'N/A'){Get-Date ((0..7 | %{([datetime]"11/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Tuesday'})[0]) -f MM/dd/yyyy}),,Y,Election Day,Polls$cycle
                $(Get-Date ([datetime]"11/11/$year") -f MM/dd/yyyy),,Y,Veterans Day,Nov 11th
                $(Get-Date ((0..29 | %{([datetime]"11/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Thursday'})[3]) -f MM/dd/yyyy),,Y,Thanksgiving,Last Thu in Nov.
                $(Get-Date (((0..29 | %{([datetime]"11/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Thursday'})[3]).AddDays(1)) -f MM/dd/yyyy),,N,Black Friday,Day after Thanksgiving
                $(Get-Date ([datetime]"12/24/$year") -f MM/dd/yyyy),,N,Christmas Eve,Dec 24th
                $(Get-Date ([datetime]"12/25/$year") -f MM/dd/yyyy),,Y,Christmas,Dec 25th
                $(Get-Date ([datetime]"12/31/$year") -f MM/dd/yyyy),,N,New Years Eve,Dec 31st
                "| ConvertFrom-Csv -Header Date,DoW,Obsrvd,Holiday,Remarks
                # Correct for Sat-Sun offsets
                    $HolidaysInYear | %{ If ((Get-Date $_.Date).DayOfWeek -eq 'Saturday'){$_.Date = (Get-Date (Get-Date ($_.Date)).AddDays(-1) -f MM/dd/yyyy) }}
                    $HolidaysInYear | %{ If ((Get-Date $_.Date).DayOfWeek -eq 'Sunday'){$_.Date = (Get-Date (Get-Date ($_.Date)).AddDays(+1) -f MM/dd/yyyy) }}
                # Populate DoW Field
                    $HolidaysInYear | %{$_.DoW = ((Get-Date ($_.Date)).DayOfWeek) }
            If ($test.IsPresent){ Return $HolidaysInYear.Date -contains (Get-date -f MM/dd/yyyy) }
            Else{ Return $HolidaysInYear }
        }

        Get-FedHolidays | Where Obsrvd -eq 'y' | OGV -Title "Federal Holidays ($((Get-Date).Year))"
        Get-FedHolidays -test
    #endregion
