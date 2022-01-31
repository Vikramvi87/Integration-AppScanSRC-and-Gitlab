# Integration AppScan Source (SAST) and Gitlab
</br>
It will help to Integrate AppScan Source on Gitlab. It will enable Gitlab to start scan, generate report, publish results to AppScan Source Database and AppScan Enterprise and check for Security Gate.<br>
<br>
Requirements:<br>
1 - AppScan Source in Windows Server (it was tested on Windows 2019).<br>
2 - Add AppScan Source bin folder to Windows PATH Environment Variable.<br>
3 - Install Gitlab Runner for Windows in same Windows Server that has AppScan Source.<br>
3.1 - Add Gitlab Runner as a Service.<br>
3.2 - Change User Service to same User that has access in AppScan Enterprise.<br>
4 - Enable Long Paths in Windows. It is not mandatory but I guess it will safe some troubleshoot time.<br>
5 - Create AppScan Enterprise token <install_dir>\bin\ounceautod.exe -u username -p password --persist.<br>
  Source: https://help.hcltechsw.com/appscan/Source/10.0.6/topics/ounce_auto_login.html <br>
  <br>

```yaml
variables:
  aseToken: C:\ProgramData\IBM\AppScanSource\config\ounceautod.token
  aseHostname: xxxxxxxxx
  aseAppName: xxxxxxxxx
  artifactFolder: $CI_PROJECT_DIR\build\libs 
  artifactName: xxxxxxxxx.war
  sevSecGw: highIssues
  maxIssuesAllowed: 80

stages:
- clean
- scan

clean-job:
  stage: clean
  script:
  - gradle clean

scan-job:
  stage: scan
  script:
  - write-host "======== Step 1 - Building artifact ========"
  - gradle build
  - write-host "======== Step 2 - Creating config scan file ========"
  - echo "login_file $aseHostname $aseToken -acceptssl" >> script.scan
  - echo "RUNAS AUTO" >> script.scan
  - echo "oa $artifactFolder\$artifactName -appserver_type Tomcat7 -no_ear_project" >> script.scan
  - echo "ra $artifactFolder\$artifactName.ozasmt -scanconfig Normal_scan -name $artifactName-$CI_JOB_ID" >> script.scan
  - echo "report Results zip $artifactName.zip $artifactFolder\$artifactName.ozasmt -includeSrcBefore:5 -includeSrcAfter:5 -includeTrace:definitive -includeTrace:suspect -includeHowToFix" >> script.scan
  - echo "pa $artifactFolder\$artifactName.ozasmt" >> script.scan
  - echo "publishassessase $artifactFolder\$artifactName.ozasmt -aseapplication $aseAppName -name $artifactName-$CI_JOB_ID" >> script.scan
  - echo "exit" >> script.scan
  - write-host "======== Step 3 - Scanning artifact and publishing SAST result ========"
  - AppScanSrcCli scr script.scan
  - copy $artifactFolder\$artifactName.ozasmt .
  - write-host "======== Step 4 - Checking Security Gate ========"
  - >
    [XML]$xml=Get-Content ./$artifactName.ozasmt
  - $highIssues = $xml.AssessmentRun.AssessmentStats.total_high_high_finding
  - $mediumIssues = $xml.AssessmentRun.AssessmentStats.total_high_med_finding
  - $lowIssues = $xml.AssessmentRun.AssessmentStats.total_high_low_finding
  - >
    if (( "$highIssues" -gt "$maxIssuesAllowed" ) -and ( "$sevSecGw" -eq "highIssues" )) {
      echo "There is $highIssues high issues and is allowed $maxIssuesAllowed"
      echo "Security Gate build failed"
      exit 1
    }
    elseif (( "$mediumIssues" -gt "$maxIssuesAllowed" ) -and ( "$sevSecGw" -eq "mediumIssues" )) {
      echo "There is $mediumIssues medium issues and is allowed $maxIssuesAllowed"
      echo "Security Gate build failed"
      exit 1
    }
    elseif (( "$lowIssues" -gt "$maxIssuesAllowed" ) -and ( "$sevSecGw" -eq "lowIssues" )) {
      echo "There is $lowIssues low issues and is allowed $maxIssuesAllowed"
      echo "Security Gate build failed"
      exit 1
    }
  - echo "There is $highIssues high issues, $mediumIssues medium issues and $lowIssues low issues"
  - echo "The company policy permit less than $maxIssuesAllowed $sevSecGw severity"
  - echo "Security Gate passed"

  artifacts:
    paths:
      - "*.ozasmt"
      - "*.zip"
```
