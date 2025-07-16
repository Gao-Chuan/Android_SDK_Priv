# Privacy_implementation_flaws
To detect different SDKs' problems.

# How to run static analysis
## JDK
The code is tested with openjdk version "11.0.20.1" 2023-08-24.

## Build
Rebuild with: ./gradlew clean;./gradlew build

## Run
ls apks |  xargs -I{} sh -c "timeout 7200 ./gradlew run --args='/home/xu111284/testnow/static_analysis/apks/{}' >> {}.log 2>&1"

where "apks" is the folder for apks, and 7200 seconds (two hours) is the timeout for dataflow analysis.
