# Real-world CloudTrail subset

`invictus-stratus-subset.json` holds unmodified CloudTrail records selected from the
public dataset https://github.com/invictus-ir/aws_dataset (MIT License,
Copyright (c) 2023 Invictus Incident Response). The dataset was produced by running
Stratus Red Team attack techniques in the dataset authors' own AWS account.
No events from this project's author's account are included.

Only events relevant to this lab's rules were kept (StopLogging, DeleteTrail,
ModifyImageAttribute, ConsoleLogin, PutBucketPolicy, DeleteBucketPolicy).
Records are copied as-is; only the selection and ordering differ from the source.
