
def determine_tweet_type(tweet):
    # Check for reply indicator first
    if tweet["in_reply_to_status_id"] is not None:
        tweet_type = "Reply Tweet"
    # Check boolean quote status field but make sure it's not a Retweet (of a Quote Tweet)
    elif tweet["is_quote_status"] is True and not tweet["text"].startswith("RT"):
        tweet_type = "Quote Tweet"
    # Check both indicators of a Retweet
    elif tweet["text"].startswith("RT") and tweet.get("retweeted_status") is not None:
        tweet_type = "Retweet"
    else:
        tweet_type = "Original Tweet"
    return tweet_type


parsedTweets = []

def parse_tweets(status):
    for tweet in status:
        if determine_tweet_type(tweet._json) == 'Retweet':
            if 'extended_tweet' in tweet._json['retweeted_status']:
                full_text = tweet._json['retweeted_status']['extended_tweet']['full_text']
            else:
                full_text = tweet._json['retweeted_status']['text']


        elif determine_tweet_type(tweet._json) == 'Quote Tweet':
            if 'extended_tweet' in tweet._json['quoted_status']:
                full_text = tweet._json['quoted_status']['extended_tweet']['full_text']
            else:
                full_text = tweet._json['quoted_status']['text']

        else:
            if 'extended_tweet' in tweet._json:
                full_text = tweet._json['extended_tweet']['full_text']
            else:
                full_text = tweet._json['text']

        mydict = { "tweet_id": tweet._json["id_str"],
                "date":tweet._json["created_at"],
                "full_text": full_text,
                "tweet_type": determine_tweet_type(tweet._json),
                "reply_count": tweet._json["reply_count"], #Number of times Tweet has been replied to
                "quote_count": tweet._json["quote_count"], # Number of times Tweet has been quoted
                "likes_count": tweet._json["favorite_count"], #Number of times Tweet has been liked
                "retweet_counts": tweet._json["retweet_count"], #Number of times this Tweet has been retweeted
                "profile_image": tweet._json["user"]["profile_image_url_https"], #Profile image URL
                "hyperlink": "https://twitter.com/twitter/status/" + tweet._json["id_str"]
            }
        parsedTweets.append(mydict) # Add Tweet to parsedTweets list
    return parsedTweets
