resource "aws_iam_role" "this" {
  name               = "${var.name_prefix}-agent-role"
  assume_role_policy = jsonencode({})
  tags               = var.tags
}

resource "aws_iam_policy" "explicit_denies" {
  name   = "${var.name_prefix}-explicit-denies"
  policy = jsonencode({ Version = "2012-10-17", Statement = [] })
}

resource "aws_iam_policy" "s3_read" {
  name   = "${var.name_prefix}-s3-read"
  policy = jsonencode({ Version = "2012-10-17", Statement = [] })
}

resource "aws_iam_role_policy_attachment" "explicit_denies_attach" {
  role       = aws_iam_role.this.name
  policy_arn = aws_iam_policy.explicit_denies.arn
}

resource "aws_iam_role_policy_attachment" "s3_read_attach" {
  role       = aws_iam_role.this.name
  policy_arn = aws_iam_policy.s3_read.arn
}
