using System;

using NHashcash;

namespace Demo
{
    // https://en.wikipedia.org/wiki/Hashcash

    /*
    Hashcash is a proof-of-work algorithm that requires a selectable amount of work to compute, but the proof can be verified efficiently. 
    For email uses, a textual encoding of a hashcash stamp is added to the header of an email to prove the sender has expended a modest 
    amount of CPU time calculating the stamp prior to sending the email. In other words, as the sender has taken a certain amount of time 
    to generate the stamp and send the email, it is unlikely that they are a spammer. The receiver can, at negligible computational cost, 
    verify that the stamp is valid. However, the only known way to find a header with the necessary properties is brute force, 
    trying random values until the answer is found; though testing an individual string is easy, if satisfactory answers are rare enough it 
    will require a substantial number of tries to find the answer.

    The hypothesis is that spammers, whose business model relies on their ability to send large numbers of emails with very little cost per 
    message, will cease to be profitable if there is even a small cost for each spam they send. Receivers can verify whether a sender made 
    such an investment and use the results to help filter email.

    The header line looks something like this:
    X-Hashcash: 1:20:1303030600:adam@cypherspace.org::McMybZIhxKXu57jd:ckvi

    The header contains:

    ver: Hashcash format version, 1 (which supersedes version 0).
    bits: Number of "partial pre-image" (zero) bits in the hashed code.
    date: The time that the message was sent, in the format YYMMDD[hhmm[ss]].
    resource: Resource data string being transmitted, e.g., an IP address or email address.
    ext: Extension (optional; ignored in version 1).
    rand: String of random characters, encoded in base-64 format.
    counter: Binary counter (up to 220), encoded in base-64 format.

    Sender's side:

    The sender prepares a header and appends a counter value initialized to a random number. It then computes the 160-bit SHA-1 hash of the header. 
    If the first 20 bits of the hash are all zeros, then this is an acceptable header. If not, then the sender increments the counter and tries 
    the hash again. Out of 2160 possible hash values, there are 2140 hash values that satisfy this criterion. Thus the chance of randomly 
    selecting a header that will have 20 zeros as the beginning of the hash is 1 in 220. The number of times that the sender needs to try before 
    getting a valid hash value is modeled by geometric distribution. Hence the sender will on average have to try 220 (a little more than a million) 
    counter values to find a valid header. Given reasonable estimates of the time needed to compute the hash,[when?] this would take 
    about 1 second to find. At this time, no more efficient method is known to find a valid header.

    A normal user on a desktop PC would not be significantly inconvenienced by the processing time required to generate the Hashcash string. 
    However, spammers would suffer significantly due to the large number of spam messages sent by them.

    Recipient's side:

    Technically the system is implemented with the following steps:

    The recipient's computer calculates the 160-bit SHA-1 hash of the entire string (e.g., "1:20:060408:adam@cypherspace.org::1QTjaYd7niiQA/sc:ePa"). 
    This takes about two microseconds on a 1 GHz machine, far less time than the time it takes for the rest of the e-mail to be received. 
    If the first 20 bits are not all zero, the hash is invalid. (Later versions may require more bits to be zero as machine processing speeds increase.)
    
    The recipient's computer checks the date in the header (e.g., "060408", which represents the date 8 Apr 2006). If it is not within 
    two days of the current date, it is invalid. (The two-day window compensates for clock skew and network routing time between different systems.)
    
    The recipient's computer checks whether the e-mail address in the hash string matches any of the valid e-mail addresses registered by 
    the recipient, or matches any of the mailing lists to which the recipient is subscribed. If a match is not found, the hash string is invalid.
    
    The recipient's computer inserts the hash string into a database. If the string is already in the database (indicating that an attempt 
    is being made to re-use the hash string), it is invalid.
    
    If the hash string passes all of these tests, it is considered a valid hash string. All of these tests take far less time and disk space 
    than receiving the body content of the e-mail.
    */

    class Program
    {
        static int iterations = 100;

        static void Main(string[] args)
        {
            TestHashCash();
            // TestNHashCash();

            Console.WriteLine("Press ENTER to exit...");
            Console.ReadLine();
        }

        static void TestHashCash()
        {
            var check = HashCash.Verify("1:20:1303030600:adam@cypherspace.org::McMybZIhxKXu57jd:ckvi");
            Console.WriteLine(check ? "Passed Verification" : "Failed Verification");

            int totalTime = 0;

            for (int i = 0; i < iterations; i++)
            {
                try
                {
                    HashCash hc = new HashCash("foo.bar@foobar.com");
                    DateTime start = DateTime.Now;
                    string header = hc.Compute();
                    DateTime stop = DateTime.Now;
                    bool ret = HashCash.Verify(header);

                    if (!ret)
                    {
                        throw new HashCashException("Verification failed.");
                    }

                    int ms = (int)((stop - start).TotalMilliseconds);
                    Console.WriteLine(i + "-> Time: " + ms + "ms   Iterations = " + hc.Iterations);
                    totalTime += ms;
                }
                catch (HashCashException ex)
                {
                    Console.WriteLine(ex.Message);
                    break;
                }
            }

            Console.WriteLine("Average time: " + (int)(totalTime / iterations) + "ms");
        }

        static void TestNHashCash()
        {
            for (int i = 0; i < iterations; i++)
            {
                Minter minter = new Minter();
                string header = minter.Mint("foo.bar@foobar.com", Minter.StampFormat.Version1);
                bool ret = HashCash.Verify(header);

                Console.WriteLine((ret ? "Passed" : "Failed") + "   " + header);
            }
        }
    }
}
