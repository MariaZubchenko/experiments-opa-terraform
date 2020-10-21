# Experiments OPA Terraform
Experiments with Open Policy Agent and Terraform 

## To check policy kms:
`$ opa eval --format pretty --data policy-kms.rego --input tfplankms.json "data.terraform"`

and if your values are allowed you will get:

```
{
  "allowed_actions": [
    "kms:*"
  ],
  "allowed_name": [
    "test_role"
  ],
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
    "Name other_value not allowed."
  ]
}
```

            
