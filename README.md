# Experiments OPA Terraform
Experiments with Open Policy Agent and Terraform 

## To check policy kms:
`$ opa eval --format pretty --data policy-kms.rego --input tfplan-kms.json "data.terraform"`

and if your values are allowed you will get:

```
{
  "allowed_name": [
    "test_role"
  ],
  "denied_action": "kms:*",
  "deny": []
}
```
if you have "name": other value
```
...
"test_role": [
              {
              ...
                "name": "test_role" 
              }
...              
```
so you will get:
```
...
  "deny": [
    "Name other not allowed."
  ]
}
```

if you have "Action": "kms:*"
```
...
 {
                                            "Action": ["kms:*"],      
                                            "Effect": "Allow",   
...
```
so you will get:
```
...
  "deny": [
    "Action kms [\"kms:*\"] not allowed."
  ]
}
```
## To check security groups:
`$ opa eval --format pretty --data policy-sg.rego --input tfplan-sg.json "data.terraform"`

and if your values are allowed you will get:
```
{
  "denied_action": "0.0.0.0/0",
  "deny": []
}
```
If you have:
```
...
"ingress": [
                  {
                    "cidr_blocks": [
                      "0.0.0.0/0"
                    ],
                    "from_port": 22,
                    "protocol": "tcp",
                    "to_port": 22
                  }
                ],
...                
```       
so you will get:
```
{
  "denied_action": "0.0.0.0/0",
  "deny": [
    "Cidr block with [\"0.0.0.0/0\"] from port 22 not allowed."
  ]
}
```
### What about base.rego, test-sse.rego, test-iam.rego:
These are not working policies as they should be.
For check this:
`$ opa eval --format pretty --data test-iam.rego --data base.rego --input test.json "data.terraform"`
or
`$ opa eval --format pretty --data test-sse.rego --data base.rego --input test.json "data.terraform"`

### policy-test.rego is for demo, how work opa policy with terraform plan.
`$ opa eval --format pretty --data policy-test.rego --input test.json "data.terraform"`
