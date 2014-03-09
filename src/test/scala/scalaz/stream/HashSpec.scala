package scalaz.stream

import java.security.MessageDigest
import org.scalacheck._
import Prop._

import Process._
import hash._

object HashSpec extends Properties("hash") {
  def digest(algo: String, str: String): List[Byte] =
    MessageDigest.getInstance(algo).digest(str.getBytes).toList

  def checkDigest(h: Process1[Bytes,Bytes], algo: String, str: String): Boolean = {
    val n = math.max(str.length / 4, 1)
    val p =
      if (str.isEmpty) emit(Bytes.unsafe(str.getBytes))
      else emitSeq(Bytes.unsafe(str.getBytes).grouped(n).toSeq)

    p.pipe(h).map(_.toArray.toList).toList == List(digest(algo, str))
  }

  property("all") = forAll { (s: String) =>
    ("md2" |: checkDigest(md2, "MD2", s)) &&
    ("md5" |: checkDigest(md5, "MD5", s)) &&
    ("sha1"   |: checkDigest(sha1,   "SHA-1",   s)) &&
    ("sha256" |: checkDigest(sha256, "SHA-256", s)) &&
    ("sha384" |: checkDigest(sha384, "SHA-384", s)) &&
    ("sha512" |: checkDigest(sha512, "SHA-512", s))
  }

  property("empty input") = secure {
    emitSeq(Seq.empty[Bytes]).pipe(sha1).toList == List()
  }
}
