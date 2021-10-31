rule Melissa

    {

            meta:

                    author = "Aswin Vijay"
                    description = "Melissa Virus"
                    date = "2021-09-18"                  

            strings:
                $creator="by Kwyjibo"
				$a1= "Works in both Word 2000 and Word 97"
				$a2 = "Worm? Macro Virus? Word 97 Virus? Word 2000 Virus? You Decide!"
               	$a3 = "Word -> Email | Word 97 <--> Word 2000 ... it's a new age!"
				$a4 = "Outlook"
                $virus = "Melissa" nocase wide
                $spam= "don't show anyone else"
                $key = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\"                                                              

            condition:

                              (all of ($a*) and $key) or
                              ($creator and $virus and $key) or
                              ($virus and $spam and $key) or
                              ($creator and $spam and $key)
    } 