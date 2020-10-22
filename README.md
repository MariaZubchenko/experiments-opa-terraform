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
"test_role": [
              {
              ...
                "name": "test_role" 
              }
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
  "deny": [
    "Action kms [\"kms:*\"] not allowed."
  ]
}
```

            
