import HeroSection from "./hero-section";
import HowItWorks from "./how-it-works";
import Categories from "./categories";
import CallToAction from "./call-to-action";
import FAQs from "./faqs";
import Footer from "./footer";

export default function Home() {
  return (
    <div className="bg-white dark:bg-background">
      <HeroSection />
      <HowItWorks />
      <Categories />
      <FAQs />
      <CallToAction />
      <Footer />
    </div>
  );
}
