using objects;
using question2.Interfaces;
using System.Reflection.Metadata.Ecma335;

namespace Logic
{
    public class PaymentLogic : IPaymentLogic
    {
        private Dictionary<int, PaymentRequest> inmemory_payments = [];
        private List<PaymentRequest> inmemory_payments_ = [];
        public void InitiatePayment(PaymentRequest paymentRequest)
        {
            inmemory_payments_.Add(paymentRequest);
        }

        public PaymentRequest GetPayment(string id)
        {
            return inmemory_payments_.Where(p=>p.Id == int.Parse(id)).FirstOrDefault()!;
        }

        public List<PaymentRequest> GetAllPayments()
        {
            return inmemory_payments_;
        }
    }
}