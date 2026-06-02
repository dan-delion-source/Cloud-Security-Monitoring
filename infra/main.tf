module "vpc" {
  source = "./modules/vpc"
}

module "dynamodb" {
  source = "./modules/dynamodb"
}

module "s3" {
  source = "./modules/s3"
}

module "cloudtrail" {
  source      = "./modules/cloudtrail"
  bucket_name = module.s3.cloudtrail_bucket_name
}

module "iam" {
  source = "./modules/iam"
}

module "sns" {
  source = "./modules/sns"
}

module "sqs" {
  source        = "./modules/sqs"
  sns_topic_arn = module.sns.topic_arn
}

module "lambda" {
  source        = "./modules/lambda"
  sqs_queue_arn = module.sqs.queue_arn
}

module "ec2" {
  source            = "./modules/ec2"
  public_subnet_id  = module.vpc.public_subnet_id
  private_subnet_id = module.vpc.private_subnet_id
  security_group_id = module.vpc.web_sg_id
}
