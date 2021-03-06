
#include <linux/module.h>
#include <net/mptcp.h>
/* defines which path to use */
#include <net/sock.h>

struct appchoice_priv {

};


static bool mptcp_is_appchoice_unavailable(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Set of states for which we are allowed to send data */
	if (!mptcp_sk_can_send(sk))
		return true;

	/* We do not send data on this subflow unless it is
	 * fully established, i.e. the 4th ack has been received.
	 */
	if (tp->mptcp->pre_established)
		return true;

	if (tp->pf)
		return true;

	return false;
}

/* Is the sub-socket sk available to send the skb? */
static bool mptcp_is_appchoice_available(struct sock *sk, const struct sk_buff *skb,
		bool zero_wnd_test)
{
	return !mptcp_is_appchoice_unavailable(sk);
}

static bool appchoice_subflow_is_backup(const struct tcp_sock *tp)
{
	return tp->mptcp->rcv_low_prio || tp->mptcp->low_prio;
}

static bool appchoice_subflow_is_active(const struct tcp_sock *tp)
{
	return !tp->mptcp->rcv_low_prio && !tp->mptcp->low_prio;
}

/* Generic function to iterate over used and unused subflows and to select the
 * best one
 */
static struct sock
*get_appchoice_subflow_from_selectors(struct mptcp_cb *mpcb, struct sk_buff *skb,
		bool (*selector)(const struct tcp_sock *),
		bool zero_wnd_test, bool *force)
{
	struct sock *fastsk = NULL;
	struct sock *slowsk = NULL;
	u32 min_srtt = 0xffffffff;
	struct sock *sk;

	mptcp_for_each_sk(mpcb, sk) {
		struct tcp_sock *tp = tcp_sk(sk);

		/* First, we choose only the wanted sks */
		if (!(*selector)(tp))
			continue;

		if (mptcp_is_appchoice_unavailable(sk))
			continue;

		/* set current fastsk as slowsk - if there is a faster sk, it doesn't get lost */
		if (fastsk)
		{
			slowsk = fastsk;
		}

		if (tp->srtt < min_srtt) {
			min_srtt = tp->srtt;
			fastsk = sk;
		}
		else
		{
			slowsk = sk;
		}
	}

	/* AppChoice Scheduler: use different links according to the flag set in the app
	 */
	if (isImportantdata)
	{
		pr_info("MPTCP Appchoice Scheduler: Important data - use slower subflow \n");
		if (slowsk)
			return slowsk;
		else
		{
			// we have a problem here but don't want to kill the connection
			pr_info("MPTCP Appchoice SCHEDULER: no slowsk found - use fastsk");
			return fastsk;
		}
	}
	else
	{
		pr_info("MPTCP Appchoice Scheduler: Unimportant data - use fastest subflow \n");
		if (fastsk)
			return fastsk;
	}
	/* should never be reached */
	pr_info("MPTCP Appchoice Scheduler: no suitable socket found \n");
	return NULL;
}

/* This is the scheduler. This function decides on which flow to send
 * a given MSS. If all subflows are found to be busy, NULL is returned
 * The flow is selected based on the shortest RTT.
 * If all paths have full cong windows, we simply return NULL.
 *
 * Additionally, this function is aware of the backup-subflows.
 */
static struct sock *appchoice_get_available_subflow(struct sock *meta_sk,
		struct sk_buff *skb,
		bool zero_wnd_test)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk;
	//true to ensure appchoice
	bool force = true;

	/* if there is only one subflow, bypass the scheduling function */
	if (mpcb->cnt_subflows == 1) {
		pr_debug("MPTCP Appchoice SCHEDULER: only one path available - bypass scheduling \n");
		sk = (struct sock *)mpcb->connection_list;
		if (!mptcp_is_appchoice_available(sk, skb, zero_wnd_test))
			sk = NULL;
		return sk;
	}

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
			skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sk(mpcb, sk) {
			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
					mptcp_is_appchoice_available(sk, skb, zero_wnd_test))
				return sk;
		}
	}

	/* Find the best subflow */
	sk = get_appchoice_subflow_from_selectors(mpcb, skb, &appchoice_subflow_is_active,
			zero_wnd_test, &force);
	if (force)
		/* one unused active sk or one NULL sk when there is at least
		 * one temporally unavailable unused active sk
		 */
		return sk;

	sk = get_appchoice_subflow_from_selectors(mpcb, skb, &appchoice_subflow_is_backup,
			zero_wnd_test, &force);
	if (!force)
		/* one used backup sk or one NULL sk where there is no one
		 * temporally unavailable unused backup sk
		 *
		 * the skb passed through all the available active and backups
		 * sks, so clean the path mask
		 */
		TCP_SKB_CB(skb)->path_mask = 0;
	return sk;
}

/* Reinjections occure here - disable for appchoice scheduler */
static struct sk_buff *mptcp_appchoice_rcv_buf_optimization(struct sock *sk, int penal)
{
	return NULL;
}

/* Returns the next segment to be sent from the mptcp meta-queue.
 * (chooses the reinject queue if any segment is waiting in it, otherwise,
 * chooses the normal write queue).
 * Sets *@reinject to 1 if the returned segment comes from the
 * reinject queue. Sets it to 0 if it is the regular send-head of the meta-sk,
 * and sets it to -1 if it is a meta-level retransmission to optimize the
 * receive-buffer.
 */
static struct sk_buff *__mptcp_appchoice_next_segment(struct sock *meta_sk, int *reinject)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sk_buff *skb = NULL;

	*reinject = 0;

	/* If we are in fallback-mode, just take from the meta-send-queue */
	if (mpcb->infinite_mapping_snd || mpcb->send_infinite_mapping)
		return tcp_send_head(meta_sk);

	skb = skb_peek(&mpcb->reinject_queue);

	if (skb) {
		*reinject = 1;
	} else {
		skb = tcp_send_head(meta_sk);

		if (!skb && meta_sk->sk_socket &&
				test_bit(SOCK_NOSPACE, &meta_sk->sk_socket->flags) &&
				sk_stream_wspace(meta_sk) < sk_stream_min_wspace(meta_sk)) {
			struct sock *subsk = appchoice_get_available_subflow(meta_sk, NULL,
					false);
			if (!subsk)
				return NULL;

			skb = mptcp_appchoice_rcv_buf_optimization(subsk, 0);
			if (skb)
				*reinject = -1;
		}
	}
	return skb;
}

static struct sk_buff *appchoice_next_segment(struct sock *meta_sk,
		int *reinject,
		struct sock **subsk,
		unsigned int *limit)
{
	struct sk_buff *skb = __mptcp_appchoice_next_segment(meta_sk, reinject);
	unsigned int mss_now;
	struct tcp_sock *subtp;
	u16 gso_max_segs;
	u32 max_len, max_segs, window, needed;

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (!skb)
		return NULL;

	*subsk = appchoice_get_available_subflow(meta_sk, skb, false);
	if (!*subsk)
		return NULL;

	subtp = tcp_sk(*subsk);
	mss_now = tcp_current_mss(*subsk);

	if (!*reinject && unlikely(!tcp_snd_wnd_test(tcp_sk(meta_sk), skb, mss_now))) {
		skb = mptcp_appchoice_rcv_buf_optimization(*subsk, 1);
		if (skb)
			*reinject = -1;
		else
			return NULL;
	}

	/* No splitting required, as we will only send one single segment */
	if (skb->len <= mss_now)
		return skb;

	/* The following is similar to tcp_mss_split_point, but
	 * we do not care about nagle, because we will anyways
	 * use TCP_NAGLE_PUSH, which overrides this.
	 *
	 * So, we first limit according to the cwnd/gso-size and then according
	 * to the subflow's window.
	 */

	gso_max_segs = (*subsk)->sk_gso_max_segs;
	if (!gso_max_segs) /* No gso supported on the subflow's NIC */
		gso_max_segs = 1;
	max_segs = min_t(unsigned int, tcp_cwnd_test(subtp, skb), gso_max_segs);
	if (!max_segs)
		return NULL;

	max_len = mss_now * max_segs;
	window = tcp_wnd_end(subtp) - subtp->write_seq;

	needed = min(skb->len, window);
	if (max_len <= skb->len)
		/* Take max_win, which is actually the cwnd/gso-size */
		*limit = max_len;
	else
		/* Or, take the window */
		*limit = needed;

	return skb;
}

static void appchoice_init(struct sock *sk)
{
}

struct mptcp_sched_ops mptcp_appchoice = {
		.get_subflow = appchoice_get_available_subflow,
		.next_segment = appchoice_next_segment,
		.init = appchoice_init,
		.name = "appchoice",
		.owner = THIS_MODULE,
};

static int __init appchoice_register(void)
{
	BUILD_BUG_ON(sizeof(struct appchoice_priv) > MPTCP_SCHED_SIZE);

	if (mptcp_register_scheduler(&mptcp_appchoice))
		return -1;

	return 0;
}

static void appchoice_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_appchoice);
}

module_init(appchoice_register);
module_exit(appchoice_unregister);

MODULE_AUTHOR("Philipp Schmitt");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MPTCP APPCHOICE SCHEDULER");
MODULE_VERSION("0.89");

