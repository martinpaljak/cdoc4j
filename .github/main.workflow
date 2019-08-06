workflow "Default workflow for pushes" {
  on = "push"
  resolves = "mvn"
}

action "mvn" {
  needs = "mvn-11"
  uses = "docker://maven:3.6.1-jdk-8"
  runs = "mvn"
  args = "-U -B verify"
}

action "mvn-11" {
  uses = "docker://maven:3.6.1-jdk-11"
  runs = "mvn"
  args = "-U -B verify"
}
