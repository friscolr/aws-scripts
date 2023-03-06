#!/usr/local/opt/python@3.9/bin/python3.9
#
# lock users console access and access keys if inactive more than specified days
# optionally, print report of users, keys, and create/last use times
#
# Fields in report (one line per user):
# username, days since last activity (keys or console), account create date, console last login date,
# access key 1 id, key 1 create date, key 1 last used date, key 1 status,  (if exists)
# access key 2 id, key 2 create date, key 2 last used date, key 2 status   (if exists)
#
# Note: actions taken print to STDERR, report prints to STDOUT
#
# Examples:
#
# First print out who would get locked that is more than 90 days inactive, then silently lock those users
#   aws-iam-lock-users.py -nd90
#   aws-iam-lock-users.py -sd90
#
# Same as previous but don't lock userids freckle and misty
#   aws-iam-lock-users.py -sd90 -S freckle,misty
#
# Just print report of all users, don't lock anything
#   aws-iam-lock-users.py -rsn

import boto3
import datetime
import sys, getopt

daysAgo = 365
silent = 0
dryRun = 0
report = 0
skipUsers = ()

# read in arguments
opts, args = getopt.getopt(sys.argv[1:], "hrsnd:S:")
for opt, arg in opts:
    if opt == "-h":
        print(
            sys.argv[0]
            + """ -rhsln -d [days] -S [user1,user2,user3]
  -h          print this help message and exit
  -r          print report on all users
  -s          silent; do not print actions taken
  -n          dry run, print actions taken but don't actually take action
  -d [days]   take actions on accounts with this many days inactivity
  -S [user]   comma separated list of usernames to skip
"""
        )
        sys.exit()
    elif opt == "-d":
        daysAgo = int(arg)
    elif opt == "-s":
        silent = 1
    elif opt == "-l":
        lock = 1
    elif opt == "-n":
        dryRun = 1
    elif opt == "-r":
        report = 1
    elif opt == "-S":
        skipUsers = arg.split(",")


resource = boto3.resource("iam")
client = boto3.client("iam")
today = datetime.datetime.now()


# run through each user, setting last access time and last service key access times
# and locking user/keys as necessary
for user in resource.users.all():

    # determine if user has console access and set create date of that access
    login_profile = resource.LoginProfile(user.user_name)
    try:
        login_profile.create_date
    except Exception as e:
        login_profile_create_date = "None"
    else:
        login_profile_create_date = login_profile.create_date

    # determine last password use and lock console access if necessary
    if login_profile_create_date == "None":
        last_access = user.create_date
        line = "," + str(user.create_date) + ",None"
    else:
        line = "," + str(user.create_date) + "," + str(user.password_last_used)
        last_access = user.password_last_used
        if last_access is None:
            last_access = user.create_date
        delta = (today - last_access.replace(tzinfo=None)).days
        if (daysAgo == 0 or delta >= daysAgo) and user.user_name not in skipUsers:
            if silent == 0:
                print("locking user " + user.user_name, file=sys.stderr)

            if dryRun == 0:
                client.delete_login_profile(UserName=user.user_name)


    # run through any access keys for the user, get service key dates and lock if necessary
    keys_response = client.list_access_keys(UserName=user.user_name)
    for key in keys_response["AccessKeyMetadata"]:
        last_used_response = client.get_access_key_last_used(
            AccessKeyId=key["AccessKeyId"]
        )

        if "LastUsedDate" in last_used_response["AccessKeyLastUsed"]:
            accesskey_last_used = last_used_response["AccessKeyLastUsed"][
                "LastUsedDate"
            ]
            line += ','.join(
                [
                    '',
                    key["AccessKeyId"],
                    str(key["CreateDate"]),
                    str(accesskey_last_used),
                    key["Status"]
                ]
            )
        else:
            accesskey_last_used = key["CreateDate"]
            line += ','.join(
                [
                    '',
                    key["AccessKeyId"],
                    str(accesskey_last_used),
                    'None',
                    key["Status"]
                ]
            )

        if accesskey_last_used > last_access:
            last_access = accesskey_last_used

        if key["Status"] == "Active":
            delta = (today - accesskey_last_used.replace(tzinfo=None)).days

            if (daysAgo == 0 or delta >= daysAgo) and user.user_name not in skipUsers:
                if silent == 0:
                    print(
                        "locking access key for user " + user.user_name, file=sys.stderr
                    )

                if dryRun == 0:
                    response = client.update_access_key(
                        UserName=user.user_name,
                        AccessKeyId=key["AccessKeyId"],
                        Status="Inactive",
                    )


    # print out report
    if report == 1:
        delta = (today - last_access.replace(tzinfo=None)).days
        print(user.user_name + "," + str(delta) + line)
