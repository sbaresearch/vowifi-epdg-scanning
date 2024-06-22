# Apple Carrier Bundle Evaluation



Under the following urls Apple releases IPCC Files

```
cat data/ipcc_urls.txt | cut -d"/" -f 1,2,3,4 | sort -u
http://appldnld.apple.com.edgesuite.net/content.info.apple.com
http://appldnld.apple.com/ios10.0
http://appldnld.apple.com/ios10.1.1
http://appldnld.apple.com/ios10.2
http://appldnld.apple.com/ios10.3
http://appldnld.apple.com/ios11.0
http://appldnld.apple.com/ios11.1
http://appldnld.apple.com/ios11.2
http://appldnld.apple.com/ios11.3
http://appldnld.apple.com/iOS5
http://appldnld.apple.com/iOS6
http://appldnld.apple.com/iOS6.1
http://appldnld.apple.com/iOS7
http://appldnld.apple.com/iOS7.1
http://appldnld.apple.com/iOS8
http://appldnld.apple.com/ios8.1
http://appldnld.apple.com/iOS8.1
http://appldnld.apple.com/iOS8.1.1
http://appldnld.apple.com/ios8.1.3
http://appldnld.apple.com/ios8.3
http://appldnld.apple.com/ios9
http://appldnld.apple.com/ios9.1
http://appldnld.apple.com/iOS9.1
http://appldnld.apple.com/ios9.2
http://appldnld.apple.com/iOS9.3
http://appldnld.apple.com/iPhone
http://appldnld.apple.com/watchos4.2.2
https://updates.cdn-apple.com/2018
https://updates.cdn-apple.com/2019
https://updates.cdn-apple.com/2020
https://updates.cdn-apple.com/2021
https://updates.cdn-apple.com/2022
https://updates.cdn-apple.com/202203
https://updates.cdn-apple.com/20220506
https://updates.cdn-apple.com/20220520
https://updates.cdn-apple.com/202206043
https://updates.cdn-apple.com/20220720
https://updates.cdn-apple.com/20220812
https://updates.cdn-apple.com/20220916
https://updates.cdn-apple.com/20220923
https://updates.cdn-apple.com/20221024
https://updates.cdn-apple.com/20221213
https://updates.cdn-apple.com/20230203
https://updates.cdn-apple.com/20230327
https://updates.cdn-apple.com/20230505
https://updates.cdn-apple.com/20230602
https://updates.cdn-apple.com/20230807
https://updates.cdn-apple.com/20230918
https://updates.cdn-apple.com/20231003
https://updates.cdn-apple.com/20231025
https://updates.cdn-apple.com/20231027
https://updates.cdn-apple.com/20231211
http://updates-http.cdn-apple.com/2018
```

The files for a provider might have been updated over the years so we can find a file in any of those urls, e.g. Hutchison => Drei in Austria

```
cat data/ipcc_urls.txt | grep "_at_" | grep Hutchison
http://appldnld.apple.com/iOS5/CarrierBundles/041-6181.20120608.54fth/Hutchison_at_iPad.ipcc
http://appldnld.apple.com/iOS7.1/CarrierBundles/031-03406.20140620.T7odn/Hutchison_at_iPhone.ipcc
http://appldnld.apple.com/iOS7.1/CarrierBundles/091-2897.20140620.jh12A/Hutchison_at_iPad.ipcc
http://appldnld.apple.com/iOS7/CarrierBundles/091-2782.20131204.PTegt/Hutchison_at_iPhone.ipcc
http://appldnld.apple.com/iOS8/CarrierBundles/031-04612.20140917.jPzQs/Hutchison_at_iPad.ipcc
http://appldnld.apple.com/iOS8/CarrierBundles/031-04817.20140917.otuUK/Hutchison_at_iPhone.ipcc
http://appldnld.apple.com/iOS9.3/carrierbundles/031-34684-20160520-406EA30C-1DEC-11E6-BAC7-A12A5529DBDF/Hutchison_at_iPhone.ipcc
http://appldnld.apple.com/iPhone/CarrierBundles/061-9494.20101112.Phly6/Hutchison_at_iPhone.ipcc
http://appldnld.apple.com/iPhone/CarrierBundles/061-9682.20101112.Vgtr5/Hutchison_at_iPad.ipcc
http://appldnld.apple.com/ios9/carrierbundles/031-31784-20150916-197270C8-565D-11E5-BCB5-6AF16CA99CB1/Hutchison_at_iPhone.ipcc
https://updates.cdn-apple.com/2019/carrierbundles/041-32098-20190204-FC8B35BC-28BD-11E9-9F6D-FC076C784515/Hutchison_at_iPhone.ipcc
https://updates.cdn-apple.com/2021/carrierbundles/071-96237/4B5C4FD5-FC73-4400-8319-AFEE9C80E41F/Hutchison_at_iPhone.ipcc
```



If we look at the latest Update (https://updates.cdn-apple.com/2021/carrierbundles/071-96237/4B5C4FD5-FC73-4400-8319-AFEE9C80E41F/Hutchison_at_iPhone.ipcc) from 2021 we can see different plist files 

