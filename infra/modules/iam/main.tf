resource "aws_iam_user" "normal_user" {
  name = "normal-user"
  path = "/"

  tags = {
    Name = "normal-user"
  }
}

resource "aws_iam_user_policy_attachment" "normal_user_readonly" {
  user       = aws_iam_user.normal_user.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_user" "suspicious_user" {
  name = "suspicious-user"
  path = "/"

  tags = {
    Name = "suspicious-user"
  }
}

resource "aws_iam_user_policy_attachment" "suspicious_user_admin" {
  user       = aws_iam_user.suspicious_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
