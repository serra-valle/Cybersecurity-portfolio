package main

deny[msg] {
    msg := data.aegis.iam.deny[_]
}

deny[msg] {
    msg := data.aegis.aws.storage.deny[_]
}

deny[msg] {
    msg := data.aegis.azure.storage.deny[_]
}
