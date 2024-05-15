import {
  Button,
  Flex,
  FlexItem,
  HelperText,
  MenuToggle,
  MenuToggleElement,
  Modal,
  ModalVariant,
  Select,
  SelectList,
  SelectOption,
} from '@patternfly/react-core';
import React from 'react';
import {AlertVariant} from 'src/atoms/AlertState';
import {useAlerts} from 'src/hooks/UseAlerts';
import {useManageOrgSubscriptions} from 'src/hooks/UseMarketplaceSubscriptions';

interface OrgSubscriptionModalProps {
  modalType: string;
  org: string;
  subscriptions: Array<Dict<string>>;
  isOpen: boolean;
  handleModalToggle: any;
}

export default function OrgSubscriptionModal(props: OrgSubscriptionModalProps) {
  const [selectedSku, setSelectedSku] = React.useState('');
  const [menuIsOpen, setMenuIsOpen] = React.useState(false);
  const {addAlert} = useAlerts();
  const onSelect = (
    _event: React.MouseEvent<Element, MouseEvent> | undefined,
    value: string | number | undefined,
  ) => {
    setSelectedSku(value as string);
    setMenuIsOpen(false);
  };

  const {
    manageSubscription,
    errorManageSubscription,
    successManageSubscription,
  } = useManageOrgSubscriptions(props.org, {
    onSuccess: () => {
      addAlert({
        variant: AlertVariant.Success,
        title: `Successfully ${
          props.modalType === 'attach' ? 'attached' : 'removed'
        } subscription`,
      });
    },
    onError: () => {
      addAlert({
        variant: AlertVariant.Failure,
        title: `Failed to ${
          props.modalType === 'attach' ? 'attach' : 'remove'
        } subscription`,
      });
    },
  });

  const maxPrivateRepos = 9007199254740991;

  return (
    <Modal
      variant={ModalVariant.small}
      title={
        props.modalType === 'attach'
          ? 'Attach Subscription'
          : 'Remove Subscription'
      }
      isOpen={props.isOpen}
      onClose={props.handleModalToggle}
    >
      <Flex>
        <FlexItem>
          <Select
            id="subscription-single-select"
            isOpen={menuIsOpen}
            toggle={(toggleRef: React.Ref<MenuToggleElement>) => (
              <MenuToggle
                id="subscription-select-toggle"
                ref={toggleRef}
                onClick={() => setMenuIsOpen(!menuIsOpen)}
                isExpanded={menuIsOpen}
              >
                {props.subscriptions[selectedSku]
                  ? props.subscriptions[selectedSku]?.quantity +
                    'x ' +
                    (BigInt(
                      props.subscriptions[selectedSku]?.metadata.privateRepos,
                    ) >= maxPrivateRepos
                      ? 'unlimited'
                      : props.subscriptions[selectedSku]?.metadata
                          .privateRepos) +
                    ' private repos'
                  : 'Select Subscription'}
              </MenuToggle>
            )}
            selected={selectedSku}
            onSelect={onSelect}
            onOpenChange={(isOpen) => setMenuIsOpen(isOpen)}
            shouldFocusToggleOnSelect
          >
            <SelectList id="subscription-select-list">
              {props.subscriptions.map((subscription: Dict<string>, index) => (
                <SelectOption key={subscription.id} value={index}>
                  {subscription.quantity}x{' '}
                  {subscription.metadata.privateRepos >= maxPrivateRepos
                    ? 'unlimited'
                    : subscription.metadata.privateRepos}{' '}
                  private repos
                </SelectOption>
              ))}
            </SelectList>
          </Select>
        </FlexItem>
        <FlexItem>
          <Button
            id="confirm-subscription-select"
            variant="primary"
            onClick={() => {
              props.handleModalToggle();
              manageSubscription({
                subscription: props.subscriptions[selectedSku],
                manageType: props.modalType,
              });
            }}
          >
            Confirm
          </Button>
        </FlexItem>
        <FlexItem>
          <Button
            id="cancel-subscription-select"
            variant="secondary"
            onClick={props.handleModalToggle}
          >
            Cancel
          </Button>
        </FlexItem>
      </Flex>
    </Modal>
  );
}
