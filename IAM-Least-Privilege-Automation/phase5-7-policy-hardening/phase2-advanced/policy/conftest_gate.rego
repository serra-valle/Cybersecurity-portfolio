package main

deny[msg] {
    msg := data.aegis.iam.deny[_]
}

deny[msg] {
    msg := data.aegis.aws.storage.deny[_]
}
